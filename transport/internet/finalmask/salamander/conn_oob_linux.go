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
// is restored on the first read if the socket's current limits permit it.
func (g *geckoOOBConn) SetReadBuffer(size int) error { return g.udp.SetReadBuffer(size) }

// SetWriteBuffer lets QUIC configure the underlying UDP send buffer.
func (g *geckoOOBConn) SetWriteBuffer(size int) error { return g.udp.SetWriteBuffer(size) }

// restoreReadBuffer attempts to undo QUIC's automatic receive buffer increase.
// Socket limits can change after the size was recorded. A tuning failure must
// still allow reads using the buffer the kernel granted.
func (g *geckoOOBConn) restoreReadBuffer(size int) {
	raw, err := g.udp.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		current, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		if err != nil || current == size {
			return
		}
		// Linux reports twice the requested size, including bookkeeping space.
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, size/2); err != nil {
			return
		}
		current, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		if err == nil && current != size {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, size/2)
		}
	})
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
	g.readMu.Lock()
	defer g.readMu.Unlock()
	if g.receiveBuffer != 0 {
		g.restoreReadBuffer(g.receiveBuffer)
		g.receiveBuffer = 0
	}
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
	for start := 0; start < len(p); start += segmentSize {
		if p[start]&geckoFlagFragment != 0 {
			return 0, 0, errors.New("gecko: fragmented packet in UDP segment batch")
		}
	}
	written := 0
	for written < len(p) {
		end := written + min(segmentSize, len(p)-written)
		n, _, err := g.writePacket(p[written:end], control, addr)
		written += n
		if err != nil {
			return written, 0, err
		}
	}
	return written, len(oob), nil
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
