package salamander

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"syscall"

	"github.com/xtls/xray-core/common/bytespool"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

type geckoUDPConn struct {
	*geckoConn
	udp *net.UDPConn
}

func wrapGeckoUDP(conn *geckoConn) (net.PacketConn, uint16) {
	udp, ok := conn.PacketConn.(*net.UDPConn)
	if !ok || udp.RemoteAddr() != nil {
		return conn, 0
	}
	return &geckoUDPConn{geckoConn: conn, udp: udp}, 1200
}

func (c *geckoUDPConn) SyscallConn() (syscall.RawConn, error) { return c.udp.SyscallConn() }
func (c *geckoUDPConn) SetReadBuffer(size int) error          { return c.udp.SetReadBuffer(size) }
func (c *geckoUDPConn) SetWriteBuffer(size int) error         { return c.udp.SetWriteBuffer(size) }

func (c *geckoUDPConn) ReadMsgUDP(p, oob []byte) (int, int, int, *net.UDPAddr, error) {
	buffer := bytespool.Alloc(4096)
	defer bytespool.Free(buffer)
	for {
		n, nn, flags, addr, err := c.udp.ReadMsgUDP(buffer[:4096], oob)
		if err != nil {
			return 0, nn, flags, addr, err
		}
		if n <= smSaltLen {
			continue
		}
		n = c.obfs.Deobfuscate(buffer[:n], buffer)
		if n == 0 {
			continue
		}
		payload := buffer[:n]
		if payload[0]&0x80 != 0 {
			h, fragment, err := decodeFrame(payload)
			if err != nil {
				continue
			}
			assembled, ready := c.acceptChunk(addr, h, fragment)
			if !ready {
				continue
			}
			payload = assembled
		}
		if len(payload) > len(p) {
			flags |= unix.MSG_TRUNC
		}
		return copy(p, payload), nn, flags, addr, nil
	}
}

// ReadBatch must transform packets itself; exposing only SyscallConn would bypass Gecko.
func (c *geckoUDPConn) ReadBatch(messages []ipv4.Message, flags int) (int, error) {
	if len(messages) == 0 {
		return 0, nil
	}
	if flags != 0 || len(messages[0].Buffers) != 1 {
		return 0, syscall.EINVAL
	}
	m := &messages[0]
	n, nn, receivedFlags, addr, err := c.ReadMsgUDP(m.Buffers[0], m.OOB)
	if err != nil {
		return 0, err
	}
	m.N, m.NN, m.Flags, m.Addr = n, nn, receivedFlags, addr
	return 1, nil
}

func (c *geckoUDPConn) writeEncrypted(p, oob []byte, addr *net.UDPAddr) (int, int, error) {
	buffer := bytespool.Alloc(int32(len(p) + smSaltLen))
	defer bytespool.Free(buffer)
	n := c.obfs.Obfuscate(p, buffer)
	written, nn, err := c.udp.WriteMsgUDP(buffer[:n], oob, addr)
	if err != nil {
		return 0, nn, err
	}
	if written != n {
		return 0, nn, io.ErrShortWrite
	}
	return len(p), nn, nil
}

func (c *geckoUDPConn) writePacket(p, oob []byte, addr *net.UDPAddr) (int, error) {
	if len(p) > 0 && p[0]&0x80 != 0 {
		return c.writeFragmented(p, addr, func(frame []byte, _ net.Addr) (int, error) {
			n, _, err := c.writeEncrypted(frame, oob, addr)
			return n, err
		})
	}
	n, _, err := c.writeEncrypted(p, oob, addr)
	return n, err
}

func (c *geckoUDPConn) WriteMsgUDP(p, oob []byte, addr *net.UDPAddr) (int, int, error) {
	if len(p) == 0 {
		return 0, 0, nil
	}
	wireOOB := bytes.Clone(oob)
	var plainOOB []byte
	var segmentSize int
	seenSegment := false
	for rest := wireOOB; len(rest) > 0; {
		h, data, next, err := unix.ParseOneSocketControlMessage(rest)
		if err != nil {
			return 0, 0, err
		}
		if h.Level == unix.IPPROTO_UDP && h.Type == unix.UDP_SEGMENT {
			if seenSegment || len(data) != 2 {
				return 0, 0, syscall.EINVAL
			}
			seenSegment = true
			segmentSize = int(binary.NativeEndian.Uint16(data))
			if segmentSize > 65535-smSaltLen {
				return 0, 0, syscall.EINVAL
			}
			if segmentSize > 0 {
				binary.NativeEndian.PutUint16(data, uint16(segmentSize+smSaltLen))
			}
		} else {
			plainOOB = append(plainOOB, rest[:len(rest)-len(next)]...)
		}
		rest = next
	}
	if segmentSize == 0 || len(p) <= segmentSize {
		n, err := c.writePacket(p, plainOOB, addr)
		return n, len(oob), err
	}
	// Handshake packets keep Gecko's fragmentation rather than UDP segmentation.
	for offset := 0; offset < len(p); offset += segmentSize {
		if p[offset]&0x80 != 0 {
			written := 0
			for written < len(p) {
				end := min(written+segmentSize, len(p))
				n, err := c.writePacket(p[written:end], plainOOB, addr)
				written += n
				if err != nil {
					return written, len(oob), err
				}
			}
			return written, len(oob), nil
		}
	}
	// Both IP families use the conservative IPv4 payload limit and at most 64 segments.
	maxSegments := min(64, 65507/(segmentSize+smSaltLen))
	if maxSegments == 0 {
		return 0, 0, syscall.EMSGSIZE
	}
	written := 0
	for written < len(p) {
		end := min(written+maxSegments*segmentSize, len(p))
		group := p[written:end]
		count := (len(group) + segmentSize - 1) / segmentSize
		buffer := bytespool.Alloc(int32(len(group) + count*smSaltLen))
		wireLength := 0
		for offset := 0; offset < len(group); offset += segmentSize {
			part := group[offset:min(offset+segmentSize, len(group))]
			wireLength += c.obfs.Obfuscate(part, buffer[wireLength:])
		}
		control := wireOOB
		if count == 1 {
			control = plainOOB
		}
		n, _, err := c.udp.WriteMsgUDP(buffer[:wireLength], control, addr)
		bytespool.Free(buffer)
		if err != nil {
			return written, len(oob), err
		}
		if n != wireLength {
			return written, len(oob), io.ErrShortWrite
		}
		written = end
	}
	return written, len(oob), nil
}
