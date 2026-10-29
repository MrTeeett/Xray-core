package salamander

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
	"unsafe"

	quic "github.com/apernet/quic-go"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/nettest"
	"golang.org/x/sys/unix"
)

type packetOnlyConn struct{ net.PacketConn }

func geckoTestPair(t *testing.T) (quic.OOBCapablePacketConn, net.PacketConn, *net.UDPConn) {
	t.Helper()
	left, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { left.Close() })
	right, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { right.Close() })
	if err := right.SetReadBuffer(1024 * 1024); err != nil {
		t.Fatal(err)
	}
	config := &GeckoConfig{Password: "local-offload-test"}
	sender, err := NewGeckoConnClient(config, left)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sender.Close() })
	sender, initialPacketSize := sender.(*geckoConn).QUICPacketConn()
	if initialPacketSize != 1200 {
		t.Fatalf("unsafe initial packet size %d", initialPacketSize)
	}
	// Hides the UDP methods so decoding uses the original PacketConn path.
	receiver, err := NewGeckoConnServer(config, packetOnlyConn{right})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { receiver.Close() })
	oob, ok := sender.(quic.OOBCapablePacketConn)
	if !ok {
		t.Fatal("Gecko masks UDP capabilities required for QUIC GSO")
	}
	if _, ok := sender.(interface {
		ReadBatch([]ipv4.Message, int) (int, error)
	}); !ok {
		t.Fatal("Missing transformed ReadBatch; QUIC would bypass deobfuscation")
	}
	return oob, receiver, right
}

func segmentControl(size uint16) []byte {
	b := make([]byte, unix.CmsgSpace(2))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = unix.IPPROTO_UDP, unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(b[unix.CmsgLen(0):], size)
	return b
}

func TestGeckoUDPSegmentationRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name              string
		size, count, tail int
	}{
		{"short_tail", 1200, 4, 37},
		{"maximum_mtu", 1452, 8, 0},
		{"split_large_batch", 1452, 48, 19},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender, receiver, _ := geckoTestPair(t)
			payload := make([]byte, tc.size*tc.count+tc.tail)
			for i := range payload {
				payload[i] = byte(i * 37)
			}
			for i := 0; i < len(payload); i += tc.size {
				payload[i] = 0x40
			}
			original := bytes.Clone(payload)
			oob := segmentControl(uint16(tc.size))
			originalOOB := bytes.Clone(oob)
			n, _, err := sender.WriteMsgUDP(payload, oob, receiver.LocalAddr().(*net.UDPAddr))
			if err != nil || n != len(payload) {
				t.Fatalf("send: n=%d err=%v", n, err)
			}
			if !bytes.Equal(payload, original) || !bytes.Equal(oob, originalOOB) {
				t.Fatal("modified caller buffers")
			}
			receiver.SetReadDeadline(time.Now().Add(2 * time.Second))
			buffer := make([]byte, 2048)
			for offset := 0; offset < len(payload); offset += tc.size {
				n, _, err := receiver.ReadFrom(buffer)
				end := min(offset+tc.size, len(payload))
				if err != nil || !bytes.Equal(buffer[:n], payload[offset:end]) {
					t.Fatalf("offset %d: n=%d err=%v", offset, n, err)
				}
			}
		})
	}
}

func TestGeckoOOBReadPreservesECNAndFragments(t *testing.T) {
	sender, receiver, rawReceiver := geckoTestPair(t)
	leftRaw, err := sender.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var socketErr error
	if err := leftRaw.Control(func(fd uintptr) { socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1) }); err != nil || socketErr != nil {
		t.Fatalf("RECVTOS: %v %v", err, socketErr)
	}
	rightRaw, err := rawReceiver.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := rightRaw.Control(func(fd uintptr) { socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, 2) }); err != nil || socketErr != nil {
		t.Fatalf("TOS: %v %v", err, socketErr)
	}
	for _, first := range []byte{0x40, 0xc0} {
		payload := bytes.Repeat([]byte{17}, 1200)
		payload[0] = first
		if _, err := receiver.WriteTo(payload, sender.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		sender.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer, control := make([]byte, 2048), make([]byte, 256)
		n, nn, flags, addr, err := sender.ReadMsgUDP(buffer, control)
		if err != nil || flags != 0 || !bytes.Equal(buffer[:n], payload) || addr.String() != receiver.LocalAddr().String() {
			t.Fatalf("read n=%d flags=%d addr=%v err=%v", n, flags, addr, err)
		}
		messages, err := unix.ParseSocketControlMessage(control[:nn])
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, m := range messages {
			if m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_TOS && len(m.Data) > 0 && m.Data[0]&3 == 2 {
				found = true
			}
		}
		if !found {
			t.Fatal("lost ECN control message")
		}
	}
}

func TestGeckoOOBLongHeaderWrite(t *testing.T) {
	sender, receiver, _ := geckoTestPair(t)
	payload := bytes.Repeat([]byte{23}, 1200)
	payload[0] = 0xc0
	if n, _, err := sender.WriteMsgUDP(payload, nil, receiver.LocalAddr().(*net.UDPAddr)); err != nil || n != len(payload) {
		t.Fatalf("send %d %v", n, err)
	}
	receiver.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 2048)
	n, _, err := receiver.ReadFrom(buffer)
	if err != nil || !bytes.Equal(payload, buffer[:n]) {
		t.Fatalf("long-header compatibility: %v", err)
	}
}

func TestGeckoReadBatchDecryptsAndReportsTruncation(t *testing.T) {
	sender, receiver, _ := geckoTestPair(t)
	batch := sender.(interface {
		ReadBatch([]ipv4.Message, int) (int, error)
	})
	payload := bytes.Repeat([]byte{29}, 100)
	payload[0] = 0x40
	for _, size := range []int{2048, 8} {
		if _, err := receiver.WriteTo(payload, sender.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		sender.SetReadDeadline(time.Now().Add(2 * time.Second))
		messages := []ipv4.Message{{Buffers: [][]byte{make([]byte, size)}, OOB: make([]byte, 256)}}
		n, err := batch.ReadBatch(messages, 0)
		m := messages[0]
		if err != nil || n != 1 || !bytes.Equal(m.Buffers[0][:m.N], payload[:min(size, len(payload))]) {
			t.Fatalf("transformed batch: n=%d err=%v", n, err)
		}
		if (m.Flags&unix.MSG_TRUNC != 0) != (size < len(payload)) {
			t.Fatal("incorrect truncation flag")
		}
	}
}

func TestGeckoGSOMixedHeaders(t *testing.T) {
	sender, receiver, _ := geckoTestPair(t)
	payload := bytes.Repeat([]byte{31}, 2400)
	payload[0], payload[1200] = 0xc0, 0x40
	if _, _, err := sender.WriteMsgUDP(payload, segmentControl(1200), receiver.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	receiver.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 2048)
	for offset := 0; offset < len(payload); offset += 1200 {
		n, _, err := receiver.ReadFrom(buffer)
		if err != nil || !bytes.Equal(buffer[:n], payload[offset:offset+1200]) {
			t.Fatalf("mixed headers: %v", err)
		}
	}
}

func TestGeckoUDPBindAddresses(t *testing.T) {
	for _, tc := range []struct {
		name, network, peerNetwork string
		listenIP, targetIP         net.IP
	}{
		{"ipv4", "udp4", "udp4", net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 1)},
		{"ipv4_wildcard", "udp4", "udp4", net.IPv4zero, net.IPv4(127, 0, 0, 2)},
		{"ipv6", "udp6", "udp6", net.IPv6loopback, net.IPv6loopback},
		{"ipv6_wildcard", "udp6", "udp6", net.IPv6zero, net.IPv6loopback},
		{"dualstack_ipv4", "udp", "udp4", nil, net.IPv4(127, 0, 0, 2)},
		{"dualstack_ipv6", "udp", "udp6", nil, net.IPv6loopback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.network != "udp4" && !nettest.SupportsIPv6() {
				t.Skip("IPv6 sockets unavailable")
			}
			raw, err := net.ListenUDP(tc.network, &net.UDPAddr{IP: tc.listenIP})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { raw.Close() })
			peerIP := net.IPv6loopback
			level, option := unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO
			if tc.targetIP.To4() != nil {
				peerIP = net.IPv4(127, 0, 0, 1)
				level, option = unix.IPPROTO_IP, unix.IP_PKTINFO
			}
			peerRaw, err := net.ListenUDP(tc.peerNetwork, &net.UDPAddr{IP: peerIP})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { peerRaw.Close() })
			config := &GeckoConfig{Password: "local-offload-test"}
			wrapped, err := NewGeckoConnServer(config, raw)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { wrapped.Close() })
			adapted, initialPacketSize := wrapped.(*geckoConn).QUICPacketConn()
			server, ok := adapted.(quic.OOBCapablePacketConn)
			if !ok || initialPacketSize != 1200 {
				t.Fatalf("missing offload adapter: %T, initial=%d", adapted, initialPacketSize)
			}
			fd, err := server.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var socketErr error
			if err := fd.Control(func(fd uintptr) { socketErr = unix.SetsockoptInt(int(fd), level, option, 1) }); err != nil || socketErr != nil {
				t.Fatalf("packet info: %v %v", err, socketErr)
			}
			// The peer retains the original decoder and receives independent UDP datagrams.
			peer, err := NewGeckoConnClient(config, packetOnlyConn{peerRaw})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { peer.Close() })
			target := &net.UDPAddr{IP: tc.targetIP, Port: raw.LocalAddr().(*net.UDPAddr).Port}
			for _, first := range []byte{0x40, 0xc0} {
				request := bytes.Repeat([]byte{first}, 1200)
				if _, err := peer.WriteTo(request, target); err != nil {
					t.Fatal(err)
				}
				server.SetReadDeadline(time.Now().Add(2 * time.Second))
				buffer, control := make([]byte, 2048), make([]byte, 256)
				n, nn, flags, from, err := server.ReadMsgUDP(buffer, control)
				if err != nil || flags != 0 || !bytes.Equal(buffer[:n], request) {
					t.Fatalf("read n=%d flags=%d err=%v", n, flags, err)
				}
				if nn == 0 {
					t.Fatal("missing destination packet info")
				}
				control = append(control[:nn:nn], segmentControl(1200)...)
				reply := bytes.Repeat([]byte{0x40}, 2437)
				if n, _, err := server.WriteMsgUDP(reply, control, from); err != nil || n != len(reply) {
					t.Fatalf("write n=%d err=%v", n, err)
				}
				peer.SetReadDeadline(time.Now().Add(2 * time.Second))
				for offset := 0; offset < len(reply); offset += 1200 {
					n, from, err := peer.ReadFrom(buffer)
					if err != nil || !bytes.Equal(buffer[:n], reply[offset:min(offset+1200, len(reply))]) {
						t.Fatalf("reply offset=%d n=%d err=%v", offset, n, err)
					}
					if !from.(*net.UDPAddr).IP.Equal(tc.targetIP) {
						t.Fatalf("wrong reply source: got %v, want %v", from, target)
					}
				}
			}
		})
	}
}

func TestGeckoUnsupportedUDPConnKeepsPacketConnPath(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	wrapped, err := NewGeckoConnServer(&GeckoConfig{Password: "local-offload-test"}, packetOnlyConn{conn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { wrapped.Close() })
	wrapped, initialPacketSize := wrapped.(*geckoConn).QUICPacketConn()
	if initialPacketSize != 0 {
		t.Fatal("unexpected initial packet override for opaque wrapper")
	}
	if _, ok := wrapped.(quic.OOBCapablePacketConn); ok {
		t.Fatal("unexpected offload for opaque wrapper")
	}
}
