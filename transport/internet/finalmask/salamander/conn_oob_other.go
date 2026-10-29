//go:build !linux

package salamander

import "net"

func wrapGeckoUDP(conn *geckoConn) (net.PacketConn, uint16) { return conn, 0 }
