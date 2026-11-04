package salamander

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

type geckoOOBConn struct {
	*geckoConn
	udp *net.UDPConn

	receiveBuffer int
	readOnce      sync.Once
	readErr       error
	readMu        sync.Mutex
	batchConn     *ipv4.PacketConn
	messages      []ipv4.Message
}

func (g *geckoOOBConn) QUICPacketConn(enabled bool) net.PacketConn {
	if enabled {
		return g
	}
	return g.geckoConn
}

// QUICDisableGSO keeps QUIC's individual packet pacing for this wrapper.
func (g *geckoOOBConn) QUICDisableGSO() bool { return true }

func optimizeGeckoConn(g *geckoConn) net.PacketConn {
	// QUIC's raw socket path sets DF; larger padding still needs IP fragmentation.
	if g.maxPkt > geckoDefaultMaxPacket {
		return g
	}
	if udp, ok := g.PacketConn.(*net.UDPConn); ok {
		raw, err := udp.SyscallConn()
		if err != nil {
			return g
		}
		var size int
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			size, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		}); err != nil || socketErr != nil {
			return g
		}
		return &geckoOOBConn{geckoConn: g, udp: udp, batchConn: ipv4.NewPacketConn(udp), receiveBuffer: size}
	}
	return g
}

// SyscallConn exposes the UDP socket for QUIC's socket options.
func (g *geckoOOBConn) SyscallConn() (syscall.RawConn, error) { return g.udp.SyscallConn() }

// SetReadBuffer configures the underlying UDP receive buffer. The pre-mask size
// is restored on the first read after QUIC's automatic socket configuration.
func (g *geckoOOBConn) SetReadBuffer(size int) error { return g.udp.SetReadBuffer(size) }

func (g *geckoOOBConn) initRead() error {
	g.readOnce.Do(func() {
		raw, err := g.udp.SyscallConn()
		if err != nil {
			g.readErr = err
			return
		}
		var socketErr error
		g.readErr = raw.Control(func(fd uintptr) {
			size, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
			if err != nil || size == g.receiveBuffer {
				socketErr = err
				return
			}
			// Linux reports twice the requested size, including bookkeeping space.
			socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, g.receiveBuffer/2)
			if socketErr != nil {
				return
			}
			size, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
			if socketErr == nil && size != g.receiveBuffer {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, g.receiveBuffer/2)
			}
		})
		if g.readErr == nil {
			g.readErr = socketErr
		}
	})
	return g.readErr
}

// ReadMsgUDP decodes Gecko while retaining the received control messages.
func (g *geckoOOBConn) ReadMsgUDP(p, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	messages := []ipv4.Message{{Buffers: [][]byte{p}, OOB: oob}}
	received, err := g.ReadBatch(messages, 0)
	if received == 0 {
		return 0, 0, 0, nil, err
	}
	message := &messages[0]
	addr, _ = message.Addr.(*net.UDPAddr)
	return message.N, message.NN, message.Flags, addr, err
}

// ReadBatch decodes a batch without letting QUIC read masked packets from the socket.
func (g *geckoOOBConn) ReadBatch(messages []ipv4.Message, flags int) (int, error) {
	if len(messages) == 0 {
		return 0, nil
	}
	if flags != 0 {
		return 0, errors.New("gecko: unsupported batch read")
	}
	count := min(len(messages), 64)
	for i := range count {
		if len(messages[i].Buffers) != 1 {
			return 0, errors.New("gecko: unsupported batch read")
		}
	}
	if err := g.initRead(); err != nil {
		return 0, err
	}
	g.readMu.Lock()
	defer g.readMu.Unlock()
	for len(g.messages) < count {
		g.messages = append(g.messages, ipv4.Message{Buffers: [][]byte{make([]byte, finalmask.UDPSize)}})
	}
	wire := g.messages[:count]
	for i := range wire {
		wire[i].OOB = messages[i].OOB
	}
	for {
		n, err := g.batchConn.ReadBatch(wire, 0)
		decoded := 0
		for i := range n {
			packet := &wire[i]
			m := &messages[decoded]
			if packet.N <= smSaltLen {
				continue
			}
			plain := packet.Buffers[0][:packet.N]
			g.obfs.Deobfuscate(plain, plain)
			data, ready := g.decodePlain(plain[:packet.N-smSaltLen], packet.Addr)
			if !ready {
				continue
			}
			m.N, m.Addr, m.Flags = copy(m.Buffers[0], data), packet.Addr, packet.Flags
			if m.N < len(data) {
				m.Flags |= unix.MSG_TRUNC
			}
			m.NN = copy(m.OOB, packet.OOB[:packet.NN])
			if m.NN < packet.NN {
				m.Flags |= unix.MSG_CTRUNC
			}
			decoded++
		}
		if decoded > 0 || err != nil {
			return decoded, err
		}
	}
}

func (g *geckoOOBConn) writePacket(p, oob []byte, addr *net.UDPAddr) (int, int, error) {
	wire := buf.NewWithSize(int32(len(p) + smSaltLen))
	defer wire.Release()
	wire.Resize(0, int32(len(p)+smSaltLen))
	g.obfs.Obfuscate(p, wire.Bytes())
	n, oobn, err := g.udp.WriteMsgUDP(wire.Bytes(), oob, addr)
	if err == nil && n != len(wire.Bytes()) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, oobn, err
	}
	return len(p), oobn, nil
}

// WriteMsgUDP masks each GSO segment separately, preserving the Gecko wire format.
func (g *geckoOOBConn) WriteMsgUDP(p, oob []byte, addr *net.UDPAddr) (int, int, error) {
	if len(p) == 0 {
		return 0, 0, nil
	}
	var control []byte
	segmentSize := 0
	for remaining := oob; len(remaining) > 0; {
		if len(remaining) < unix.CmsgLen(0) {
			return 0, 0, errors.New("gecko: truncated control message")
		}
		header, data, rest, err := unix.ParseOneSocketControlMessage(remaining)
		if err != nil {
			return 0, 0, err
		}
		if header.Level == unix.IPPROTO_UDP && header.Type == unix.UDP_SEGMENT {
			if len(data) != 2 {
				return 0, 0, errors.New("gecko: invalid UDP segment size")
			}
			segmentSize = int(binary.NativeEndian.Uint16(data))
			if segmentSize > 65507-smSaltLen {
				return 0, 0, errors.New("gecko: UDP segment too large")
			}
		} else {
			control = append(control, remaining[:len(remaining)-len(rest)]...)
		}
		remaining = rest
	}

	if segmentSize == 0 {
		if p[0]&geckoFlagFragment != 0 {
			n, err := g.writeFragments(p, func(frame []byte) error {
				_, _, err := g.writePacket(frame, control, addr)
				return err
			})
			return n, len(oob), err
		}
		n, nn, err := g.writePacket(p, control, addr)
		if err == nil {
			nn = len(oob)
		}
		return n, nn, err
	}
	// Keep QUIC batching without coalescing datagrams into a GSO super-packet.
	written := 0
	for written < len(p) {
		end := min(len(p), written+8*segmentSize)
		n, err := g.writeSegments(p[written:end], control, addr, segmentSize)
		written += n
		if err != nil {
			return written, 0, err
		}
	}
	return written, len(oob), nil
}

func (g *geckoOOBConn) writeSegments(p, oob []byte, addr *net.UDPAddr, segmentSize int) (int, error) {
	count := (len(p) + segmentSize - 1) / segmentSize
	wire := buf.NewWithSize(int32(len(p) + count*smSaltLen))
	defer wire.Release()
	wire.Resize(0, int32(len(p)+count*smSaltLen))
	messages := make([]ipv4.Message, 0, count)
	offset := 0
	for start := 0; start < len(p); start += segmentSize {
		chunk := p[start:min(len(p), start+segmentSize)]
		if chunk[0]&geckoFlagFragment != 0 {
			return 0, errors.New("gecko: fragmented packet in UDP segment batch")
		}
		packet := wire.Bytes()[offset : offset+len(chunk)+smSaltLen]
		g.obfs.Obfuscate(chunk, packet)
		messages = append(messages, ipv4.Message{Buffers: [][]byte{packet}, OOB: oob, Addr: addr})
		offset += len(packet)
	}
	written := 0
	for len(messages) > 0 {
		n, err := g.batchConn.WriteBatch(messages, 0)
		for _, m := range messages[:n] {
			if m.N != len(m.Buffers[0]) {
				return written, io.ErrShortWrite
			}
			written += m.N - smSaltLen
		}
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrNoProgress
		}
		messages = messages[n:]
	}
	return written, nil
}

func (g *geckoOOBConn) decodePlain(wire []byte, addr net.Addr) ([]byte, bool) {
	// Short-header packets and unframed garbage are handled by QUIC.
	if wire[0]&geckoFlagFragment == 0 {
		return wire, true
	}
	h, payload, err := decodeFrame(wire)
	if err != nil {
		return nil, false
	}
	out, ready := g.acceptChunk(addr, h, payload)
	if !ready {
		return nil, false
	}
	return out, true
}
