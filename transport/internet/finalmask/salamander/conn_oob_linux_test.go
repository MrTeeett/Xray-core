package salamander

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/apernet/quic-go"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

var testPSK = []byte("gecko compatibility test password")

var _ quic.OOBCapablePacketConn = (*geckoOOBConn)(nil)

func testUDP(t *testing.T, network string) *net.UDPConn {
	t.Helper()
	host := "127.0.0.1:0"
	if network == "udp6" {
		host = "[::1]:0"
	}
	addr, err := net.ResolveUDPAddr(network, host)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenUDP(network, addr)
	if err != nil {
		if network == "udp6" {
			t.Skipf("IPv6 unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.SetReadBuffer(4 << 20); err != nil {
		t.Fatal(err)
	}
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return c
}

func testGecko(t *testing.T, raw net.PacketConn) net.PacketConn {
	t.Helper()
	c, err := NewGeckoConnServer(&GeckoConfig{Password: string(testPSK)}, raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*geckoConn).QUICPacketConn(true)
}

func segmentControl(size uint16) []byte {
	oob := make([]byte, unix.CmsgSpace(2))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level, h.Type = unix.IPPROTO_UDP, unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], size)
	return oob
}

func unmaskTestPacket(t *testing.T, wire []byte) []byte {
	t.Helper()
	if len(wire) < smSaltLen {
		t.Fatalf("short wire packet: %d", len(wire))
	}
	key := blake2b.Sum256(append(append([]byte(nil), testPSK...), wire[:smSaltLen]...))
	plain := append([]byte(nil), wire[smSaltLen:]...)
	for i := range plain {
		plain[i] ^= key[i%smKeyLen]
	}
	return plain
}

func TestGeckoGSOWireCompatibility(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, size := range []int{1200, 1452} {
			for _, count := range []int{1, 2, 8, 48, 96} {
				t.Run(fmt.Sprintf("%s/%d/%d", network, size, count), func(t *testing.T) {
					sender := testGecko(t, testUDP(t, network)).(*geckoOOBConn)
					peer := testUDP(t, network)
					var plain []byte
					var packets [][]byte
					for i := 0; i < count; i++ {
						n := size
						if i == count-1 {
							n /= 2
						}
						packet := bytes.Repeat([]byte{byte(i)}, n)
						packet[0] = 0x40
						packets = append(packets, packet)
						plain = append(plain, packet...)
					}
					oob := segmentControl(uint16(size))
					before := append([]byte(nil), oob...)
					n, nn, err := sender.WriteMsgUDP(plain, oob, peer.LocalAddr().(*net.UDPAddr))
					if err != nil || n != len(plain) || nn != len(oob) {
						t.Fatalf("write = %d, %d, %v", n, nn, err)
					}
					if !bytes.Equal(oob, before) {
						t.Fatal("modified caller's control messages")
					}
					wire := make([]byte, 4096)
					for _, expected := range packets {
						n, _, err := peer.ReadFromUDP(wire)
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(unmaskTestPacket(t, wire[:n]), expected) {
							t.Fatal("GSO changed the per-packet wire format")
						}
					}
				})
			}
		}
	}
}

func TestGeckoOOBLegacyPeer(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, first := range []byte{0x40, 0x80} {
			t.Run(fmt.Sprintf("%s/%x", network, first), func(t *testing.T) {
				a := testGecko(t, testUDP(t, network)).(*geckoOOBConn)
				b := testGecko(t, testUDP(t, network)).(*geckoOOBConn)
				raw, err := a.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var optionErr error
				if err := raw.Control(func(fd uintptr) {
					if network == "udp4" {
						optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
					} else {
						optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)
					}
				}); err != nil || optionErr != nil {
					t.Fatalf("receive control messages: %v, %v", err, optionErr)
				}
				payload := bytes.Repeat([]byte{0x35}, 1200)
				payload[0] = first
				if n, _, err := a.WriteMsgUDP(payload, nil, b.LocalAddr().(*net.UDPAddr)); err != nil || n != len(payload) {
					t.Fatalf("write = %d, %v", n, err)
				}
				out := make([]byte, 4096)
				if n, _, err := b.geckoConn.ReadFrom(out); err != nil || !bytes.Equal(payload, out[:n]) {
					t.Fatalf("legacy read = %d, %v", n, err)
				}
				if _, err := b.geckoConn.WriteTo(payload, a.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				messages := []ipv4.Message{{Buffers: [][]byte{out}, OOB: make([]byte, 128)}}
				if n, err := a.ReadBatch(messages, 0); err != nil || n != 1 || !bytes.Equal(payload, out[:messages[0].N]) {
					t.Fatalf("batch read = %d, %v", n, err)
				}
				if messages[0].Addr == nil {
					t.Fatal("missing source address")
				}
				if messages[0].NN == 0 {
					t.Fatal("discarded received control messages")
				}
			})
		}
	}
}

func TestGeckoOOBErrors(t *testing.T) {
	a := testGecko(t, testUDP(t, "udp4")).(*geckoOOBConn)
	b := testUDP(t, "udp4")
	if _, _, err := a.WriteMsgUDP([]byte{0x80}, segmentControl(1200), b.LocalAddr().(*net.UDPAddr)); err == nil {
		t.Fatal("accepted a long-header GSO batch")
	}
	invalidControl := segmentControl(1200)
	(*unix.Cmsghdr)(unsafe.Pointer(&invalidControl[0])).SetLen(len(invalidControl) + 1)
	if _, _, err := a.WriteMsgUDP([]byte{0x40}, invalidControl, b.LocalAddr().(*net.UDPAddr)); err == nil {
		t.Fatal("accepted malformed control data")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := a.ReadMsgUDP(make([]byte, 4096), nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed read: %v", err)
	}
	if n, _, err := a.WriteMsgUDP([]byte{0x40}, nil, b.LocalAddr().(*net.UDPAddr)); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed write: %d, %v", n, err)
	}
	if n, _, err := a.WriteMsgUDP(bytes.Repeat([]byte{0x40}, 2400), segmentControl(1200), b.LocalAddr().(*net.UDPAddr)); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed segmented write: %d, %v", n, err)
	}
	wrapped := struct{ net.PacketConn }{testUDP(t, "udp4")}
	if _, ok := testGecko(t, wrapped).(*geckoOOBConn); ok {
		t.Fatal("bypassed an upstream PacketConn wrapper")
	}
}

func TestGeckoQUICPreservesReceiveBuffer(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, requested := range []int{0, 32768, 262144} {
			t.Run(fmt.Sprintf("%s/%d", network, requested), func(t *testing.T) {
				ip := net.IPv4(127, 0, 0, 1)
				if network == "udp6" {
					ip = net.IPv6loopback
				}
				raw, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
				if err != nil {
					if network == "udp6" {
						t.Skipf("IPv6 unavailable: %v", err)
					}
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = raw.Close() })
				if requested != 0 {
					if err := raw.SetReadBuffer(requested); err != nil {
						t.Fatal(err)
					}
				}
				receiveBuffer := func() int {
					t.Helper()
					control, err := raw.SyscallConn()
					if err != nil {
						t.Fatal(err)
					}
					var size int
					var socketErr error
					if err := control.Control(func(fd uintptr) {
						size, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
					}); err != nil || socketErr != nil {
						t.Fatalf("receive buffer: %v, %v", err, socketErr)
					}
					return size
				}
				before := receiveBuffer()
				masked := testGecko(t, raw).(*geckoOOBConn)
				transport := &quic.Transport{Conn: masked}
				t.Cleanup(func() { _ = transport.Close() })
				listener, err := transport.Listen(&tls.Config{
					NextProtos: []string{"gecko-test"},
					GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
						return nil, errors.New("no handshake expected")
					},
				}, nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				deadline := time.Now().Add(time.Second)
				for receiveBuffer() != before && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if after := receiveBuffer(); after != before {
					t.Fatalf("QUIC changed configured receive buffer: %d -> %d", before, after)
				}
				if err := masked.SetReadBuffer(32768); err != nil {
					t.Fatal(err)
				}
				if size := receiveBuffer(); size != 65536 {
					t.Fatalf("subsequent SetReadBuffer did not apply: %d", size)
				}
			})
		}
	}
}

func TestGeckoRejectsTruncatedOOB(t *testing.T) {
	sender := testGecko(t, testUDP(t, "udp4")).(*geckoOOBConn)
	peer := testUDP(t, "udp4")
	for size := 1; size < unix.CmsgLen(0); size++ {
		control := bytes.Repeat([]byte{0xff}, size)
		n, nn, err := sender.WriteMsgUDP([]byte{0x40}, control, peer.LocalAddr().(*net.UDPAddr))
		if n != 0 || nn != 0 || err == nil {
			t.Fatalf("control size %d: wrote %d, %d, error %v", size, n, nn, err)
		}
	}
}

func TestGeckoLargePaddingKeepsFragmentation(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			raw, peer := testUDP(t, network), testUDP(t, network)
			fragmentation := func() int {
				t.Helper()
				control, err := raw.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				level, option := unix.IPPROTO_IP, unix.IP_MTU_DISCOVER
				if network == "udp6" {
					level, option = unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER
				}
				var value int
				var socketErr error
				if err := control.Control(func(fd uintptr) {
					value, socketErr = unix.GetsockoptInt(int(fd), level, option)
				}); err != nil {
					t.Fatal(err)
				}
				if socketErr != nil {
					t.Fatal(socketErr)
				}
				return value
			}
			before := fragmentation()
			masked, err := NewGeckoConnServer(&GeckoConfig{
				Password: string(testPSK), MinPacketSize: 2048, MaxPacketSize: 2048,
			}, raw)
			if err != nil {
				t.Fatal(err)
			}
			masked = masked.(*geckoConn).QUICPacketConn(true)
			t.Cleanup(func() { _ = masked.Close() })
			transport := &quic.Transport{Conn: masked}
			t.Cleanup(func() { _ = transport.Close() })
			listener, err := transport.Listen(&tls.Config{
				NextProtos: []string{"gecko-test"},
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return nil, errors.New("no handshake expected")
				},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			if after := fragmentation(); after != before {
				t.Fatalf("QUIC changed fragmentation policy: %d -> %d", before, after)
			}
			payload := bytes.Repeat([]byte{0x80}, 1200)
			if n, err := masked.WriteTo(payload, peer.LocalAddr()); err != nil || n != len(payload) {
				t.Fatalf("large padding write: %d, %v", n, err)
			}
			var chunks [][]byte
			for i := 0; i == 0 || i < len(chunks); i++ {
				wire := make([]byte, 4096)
				n, _, err := peer.ReadFromUDP(wire)
				if err != nil || n != 2048 {
					t.Fatalf("large padding packet: %d, %v", n, err)
				}
				h, chunk, err := decodeFrame(unmaskTestPacket(t, wire[:n]))
				if err != nil {
					t.Fatal(err)
				}
				if chunks == nil {
					chunks = make([][]byte, h.totalChunks)
				}
				chunks[h.chunkIdx] = append([]byte(nil), chunk...)
			}
			if !bytes.Equal(bytes.Join(chunks, nil), payload) {
				t.Fatal("large padding changed payload")
			}
		})
	}
}

func TestGeckoReadBatchDecodesAndCompacts(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			sender := testGecko(t, testUDP(t, network)).(*geckoOOBConn)
			receiver := testGecko(t, testUDP(t, network)).(*geckoOOBConn)
			addr := receiver.LocalAddr().(*net.UDPAddr)
			if _, err := sender.udp.WriteToUDP([]byte{1}, addr); err != nil {
				t.Fatal(err)
			}
			var expected [][]byte
			for i := range 9 {
				p := bytes.Repeat([]byte{byte(i)}, 1200)
				p[0] = 0x40
				if i == 0 {
					p[0] = 0xc0
				}
				expected = append(expected, p)
				if _, _, err := sender.WriteMsgUDP(p, nil, addr); err != nil {
					t.Fatal(err)
				}
			}
			messages := make([]ipv4.Message, 8)
			for i := range messages {
				messages[i].Buffers = [][]byte{make([]byte, 1452)}
				messages[i].OOB = make([]byte, 128)
			}
			received, largestBatch := 0, 0
			for received < len(expected) {
				n, err := receiver.ReadBatch(messages, 0)
				if err != nil {
					t.Fatal(err)
				}
				largestBatch = max(largestBatch, n)
				for _, m := range messages[:n] {
					if received >= len(expected) || !bytes.Equal(m.Buffers[0][:m.N], expected[received]) {
						t.Fatalf("batch payload %d changed", received)
					}
					if m.Addr.String() != sender.LocalAddr().String() {
						t.Fatalf("batch source changed: %v", m.Addr)
					}
					received++
				}
			}
			if largestBatch <= 1 {
				t.Fatal("queued packets were still read one at a time")
			}
		})
	}
}

func TestGeckoSegmentedWritePreservesECN(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			sender := testGecko(t, testUDP(t, network)).(*geckoOOBConn)
			peer := testUDP(t, network)
			level, option, kind, size := unix.IPPROTO_IP, unix.IP_RECVTOS, unix.IP_TOS, 1
			if network == "udp6" {
				level, option, kind, size = unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, unix.IPV6_TCLASS, 4
			}
			raw, err := peer.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var socketErr error
			if err := raw.Control(func(fd uintptr) {
				socketErr = unix.SetsockoptInt(int(fd), level, option, 1)
			}); err != nil || socketErr != nil {
				t.Fatalf("enable ECN: %v, %v", err, socketErr)
			}
			ecn := make([]byte, unix.CmsgSpace(size))
			header := (*unix.Cmsghdr)(unsafe.Pointer(&ecn[0]))
			header.Level, header.Type = int32(level), int32(kind)
			header.SetLen(unix.CmsgLen(size))
			if size == 1 {
				ecn[unix.CmsgLen(0)] = 2
			} else {
				binary.NativeEndian.PutUint32(ecn[unix.CmsgLen(0):], 2)
			}
			oob := append(segmentControl(1200), ecn...)
			before := append([]byte(nil), oob...)
			payload := bytes.Repeat([]byte{0x40}, 2400)
			if n, nn, err := sender.WriteMsgUDP(payload, oob, peer.LocalAddr().(*net.UDPAddr)); err != nil || n != len(payload) || nn != len(oob) {
				t.Fatalf("segmented ECN write: %d, %d, %v", n, nn, err)
			}
			if !bytes.Equal(before, oob) {
				t.Fatal("changed caller control messages")
			}
			for range 2 {
				wire, control := make([]byte, 2048), make([]byte, 128)
				n, nn, _, _, err := peer.ReadMsgUDP(wire, control)
				if err != nil || !bytes.Equal(unmaskTestPacket(t, wire[:n]), payload[:1200]) {
					t.Fatalf("segmented ECN payload: %d, %v", n, err)
				}
				messages, err := unix.ParseSocketControlMessage(control[:nn])
				if err != nil || len(messages) != 1 {
					t.Fatalf("ECN metadata missing: %v, %v", messages, err)
				}
				if len(messages[0].Data) != size {
					t.Fatalf("ECN metadata size changed: %v", messages)
				}
				mark := uint32(messages[0].Data[0])
				if size == 4 {
					mark = binary.NativeEndian.Uint32(messages[0].Data)
				}
				if int(messages[0].Header.Level) != level || int(messages[0].Header.Type) != kind || mark&3 != 2 {
					t.Fatalf("ECN metadata changed: %v", messages)
				}
			}
		})
	}
}

func TestGeckoReportsPlaintextTruncation(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, batch := range []bool{false, true} {
			for _, fragmented := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/batch=%t/fragmented=%t", network, batch, fragmented), func(t *testing.T) {
					sender := testGecko(t, testUDP(t, network)).(*geckoOOBConn)
					receiver := testGecko(t, testUDP(t, network)).(*geckoOOBConn)
					read := func(p []byte) (int, int, error) {
						if !batch {
							n, _, flags, _, err := receiver.ReadMsgUDP(p, nil)
							return n, flags, err
						}
						messages := []ipv4.Message{{Buffers: [][]byte{p}}}
						_, err := receiver.ReadBatch(messages, 0)
						return messages[0].N, messages[0].Flags, err
					}
					plain := bytes.Repeat([]byte{0x42}, 256)
					plain[0] = 0x40
					if fragmented {
						plain[0] = 0xc0
					}
					if _, _, err := sender.WriteMsgUDP(plain, nil, receiver.udp.LocalAddr().(*net.UDPAddr)); err != nil {
						t.Fatal(err)
					}
					out := make([]byte, 5)
					n, flags, err := read(out)
					if err != nil || n != len(out) || !bytes.Equal(out, plain[:len(out)]) {
						t.Fatalf("truncated read: n=%d flags=%x err=%v", n, flags, err)
					}
					if flags&unix.MSG_TRUNC == 0 {
						t.Fatalf("lost payload without MSG_TRUNC: flags=%x", flags)
					}
					next := []byte{0x40, 1, 2}
					if _, _, err := sender.WriteMsgUDP(next, nil, receiver.udp.LocalAddr().(*net.UDPAddr)); err != nil {
						t.Fatal(err)
					}
					n, flags, err = read(out)
					if err != nil || n != len(next) || flags&unix.MSG_TRUNC != 0 || !bytes.Equal(out[:n], next) {
						t.Fatalf("next read: n=%d flags=%x err=%v", n, flags, err)
					}
				})
			}
		}
	}
}
