package salamander

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"golang.org/x/crypto/blake2b"
)

func TestSalamanderByteCompatibility(t *testing.T) {
	psk := []byte("byte compatibility password")
	obfs, err := NewSalamanderObfuscator(psk)
	if err != nil {
		t.Fatal(err)
	}
	sizes := []int{512, 1200, 1452, 2040, 65500}
	for size := range 66 {
		sizes = append(sizes, size)
	}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			plain := make([]byte, size)
			for i := range plain {
				plain[i] = byte(i*37 + 11)
			}
			for _, inPlace := range []bool{false, true} {
				wire := make([]byte, size+smSaltLen)
				input := plain
				if inPlace {
					copy(wire[smSaltLen:], plain)
					input = wire[smSaltLen:]
				}
				if n := obfs.Obfuscate(input, wire); n != len(wire) {
					t.Fatalf("obfuscated length: %d", n)
				}
				key := blake2b.Sum256(append(append([]byte(nil), psk...), wire[:smSaltLen]...))
				for i, value := range plain {
					if wire[smSaltLen+i] != value^key[i%smKeyLen] {
						t.Fatalf("wire byte %d changed, in-place=%v", i, inPlace)
					}
				}
				for _, offset := range []int{-1, 0, smSaltLen} {
					packet := append([]byte(nil), wire...)
					decoded := make([]byte, size)
					if offset >= 0 {
						decoded = packet[offset : offset+size]
					}
					if n := obfs.Deobfuscate(packet, decoded); n != size || !bytes.Equal(decoded, plain) {
						t.Fatalf("decoded payload changed, offset=%d: %d", offset, n)
					}
				}
			}
		})
	}
}

func TestSalamanderShortBuffers(t *testing.T) {
	obfs, err := NewSalamanderObfuscator([]byte("short buffer test password"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		cipher  func([]byte, []byte) int
		inSize  int
		outSize int
	}{
		{"encrypt-short", obfs.Obfuscate, 1200, 1207},
		{"decrypt-short-output", obfs.Deobfuscate, 1208, 1199},
		{"decrypt-short-salt", obfs.Deobfuscate, 7, 16},
		{"decrypt-salt-only", obfs.Deobfuscate, 8, 16},
	} {
		t.Run(test.name, func(t *testing.T) {
			out := bytes.Repeat([]byte{0xa5}, test.outSize)
			before := bytes.Clone(out)
			if n := test.cipher(make([]byte, test.inSize), out); n != 0 || !bytes.Equal(out, before) {
				t.Fatalf("short buffer modified or accepted: %d", n)
			}
		})
	}
}

func TestSalamanderConcurrentObfuscation(t *testing.T) {
	obfs, err := NewSalamanderObfuscator([]byte("concurrent test password"))
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte{0x42}, 1200)
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(4)
	for range 4 {
		go func() {
			defer workers.Done()
			<-start
			wire := make([]byte, len(plain)+smSaltLen)
			decoded := make([]byte, len(plain))
			for range 1000 {
				if obfs.Obfuscate(plain, wire) != len(wire) || obfs.Deobfuscate(wire, decoded) != len(plain) || !bytes.Equal(decoded, plain) {
					t.Error("concurrent cipher calls corrupted a packet")
					return
				}
			}
		}()
	}
	close(start)
	workers.Wait()
}
