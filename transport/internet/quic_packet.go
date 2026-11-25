package internet

import "net"

// QUICPacketConn selects a mask's optimizations before QUIC configures its socket.
func QUICPacketConn(conn net.PacketConn, enabled bool) net.PacketConn {
	if masked, ok := conn.(interface {
		QUICPacketConn(bool) net.PacketConn
	}); ok {
		return masked.QUICPacketConn(enabled)
	}
	return conn
}

// QUICDisableGSO preserves explicit settings and mask-specific send pacing.
func QUICDisableGSO(conn net.PacketConn, disabled bool) bool {
	if disabled {
		return true
	}
	masked, ok := conn.(interface{ QUICDisableGSO() bool })
	return ok && masked.QUICDisableGSO()
}
