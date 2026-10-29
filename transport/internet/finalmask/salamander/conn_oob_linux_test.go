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

func TestGeckoWildcardKeepsPacketConnPath(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	wrapped, err := NewGeckoConnServer(&GeckoConfig{Password: "local-offload-test"}, conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { wrapped.Close() })
	wrapped, initialPacketSize := wrapped.(*geckoConn).QUICPacketConn()
	if initialPacketSize != 0 {
		t.Fatal("unexpected initial packet override for wildcard binding")
	}
	if _, ok := wrapped.(quic.OOBCapablePacketConn); ok {
		t.Fatal("unexpected offload for wildcard binding")
	}
}
