//go:build !linux

package salamander

import "net"

func optimizeGeckoConn(g *geckoConn) net.PacketConn { return g }
