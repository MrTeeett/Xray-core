package salamander

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

type gsoRecorder struct {
	*geckoOOBConn
	seen  atomic.Bool
	reads atomic.Uint32
}

func (r *gsoRecorder) ReadBatch(messages []ipv4.Message, flags int) (int, error) {
	r.reads.Add(1)
	return r.geckoOOBConn.ReadBatch(messages, flags)
}

func (r *gsoRecorder) WriteMsgUDP(p, oob []byte, addr *net.UDPAddr) (int, int, error) {
	controls, _ := unix.ParseSocketControlMessage(oob)
	for _, control := range controls {
		if control.Header.Level == unix.IPPROTO_UDP && control.Header.Type == unix.UDP_SEGMENT {
			r.seen.Store(true)
		}
	}
	return r.geckoOOBConn.WriteMsgUDP(p, oob, addr)
}

func TestGeckoQUICModes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"udp4", "udp6"} {
		for _, mode := range []string{"bbr", "brutal", "force-brutal"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				newEndpoint := func() net.PacketConn {
					t.Helper()
					conn, err := NewGeckoConnClient(&GeckoConfig{Password: string(testPSK)}, testUDP(t, network))
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = conn.Close() })
					selected := internet.QUICPacketConn(conn, mode == "force-brutal")
					_, optimized := selected.(*geckoOOBConn)
					if optimized != (mode == "force-brutal") {
						t.Fatal("socket mode does not match controller policy")
					}
					return selected
				}
				server := newEndpoint()
				var recorder *gsoRecorder
				if fast, ok := server.(*geckoOOBConn); ok {
					recorder = &gsoRecorder{geckoOOBConn: fast}
					server = recorder
				}

				transport := &quic.Transport{Conn: server, DisableGSO: internet.QUICDisableGSO(server, false)}
				t.Cleanup(func() { _ = transport.Close() })
				listener, err := transport.Listen(&tls.Config{
					Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
					NextProtos:   []string{"gecko-test"},
				}, nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				t.Cleanup(cancel)
				setCongestion := func(conn *quic.Conn) {
					if mode == "bbr" {
						congestion.UseBBR(conn, bbr.ProfileStandard)
					} else {
						congestion.UseBrutal(conn, 100*1000*1000/8, false)
					}
				}
				ready := make(chan bool, 1)
				done := make(chan error, 1)
				go func() {
					conn, err := listener.Accept(ctx)
					if err != nil {
						done <- err
						return
					}
					setCongestion(conn)
					ready <- conn.ConnectionState().GSO
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						done <- err
						return
					}
					deadline, _ := ctx.Deadline()
					if err := stream.SetDeadline(deadline); err != nil {
						done <- err
						return
					}
					data, err := io.ReadAll(stream)
					if err == nil {
						_, err = stream.Write(data)
					}
					if err == nil {
						err = stream.Close()
					}
					done <- err
				}()
				clientEndpoint := newEndpoint()
				clientTransport := &quic.Transport{Conn: clientEndpoint, DisableGSO: internet.QUICDisableGSO(clientEndpoint, false)}
				t.Cleanup(func() { _ = clientTransport.Close() })
				client, err := clientTransport.Dial(ctx, server.LocalAddr(), &tls.Config{
					InsecureSkipVerify: true, // Ephemeral certificate belongs to this test.
					NextProtos:         []string{"gecko-test"},
				}, nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.CloseWithError(0, "") })
				setCongestion(client)
				select {
				case enabled := <-ready:
					if enabled {
						t.Fatal("masked transport enabled send batching")
					}
				case err := <-done:
					t.Fatal(err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				stream, err := client.OpenStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				deadline, _ := ctx.Deadline()
				if err := stream.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				payload := bytes.Repeat([]byte{0x42}, 512*1024)
				if n, err := stream.Write(payload); err != nil || n != len(payload) {
					t.Fatalf("write: %d, %v", n, err)
				}
				if err := stream.Close(); err != nil {
					t.Fatal(err)
				}
				reply, err := io.ReadAll(stream)
				if err != nil || !bytes.Equal(reply, payload) {
					t.Fatalf("masked transfer: %d bytes, %v", len(reply), err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if recorder != nil && (recorder.seen.Load() || recorder.reads.Load() == 0) {
					t.Fatal("fast mode must batch receives and keep individual sends")
				}
			})
		}
	}
}
