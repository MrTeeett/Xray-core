package internet_test

import (
	"net"
	"testing"

	"github.com/xtls/xray-core/transport/internet"
)

type packetModeConn struct {
	net.PacketConn
	fast       net.PacketConn
	disableGSO bool
}

func (c *packetModeConn) QUICDisableGSO() bool { return c.disableGSO }

func (c *packetModeConn) QUICPacketConn(enabled bool) net.PacketConn {
	if enabled {
		return c.fast
	}
	return c.PacketConn
}

func TestQUICDisableGSO(t *testing.T) {
	plain := &struct{ net.PacketConn }{}
	for _, disabled := range []bool{false, true} {
		if got := internet.QUICDisableGSO(plain, disabled); got != disabled {
			t.Fatalf("plain socket changed its configured mode: %t", got)
		}
		for _, maskDisabled := range []bool{false, true} {
			masked := &packetModeConn{PacketConn: plain, disableGSO: maskDisabled}
			if got := internet.QUICDisableGSO(masked, disabled); got != (disabled || maskDisabled) {
				t.Fatalf("configured=%t, mask=%t: got %t", disabled, maskDisabled, got)
			}
		}
	}
}

func TestQUICPacketConnSelection(t *testing.T) {
	basic := &struct{ net.PacketConn }{}
	fast := &struct{ net.PacketConn }{}
	masked := &packetModeConn{PacketConn: basic, fast: fast}
	for _, enabled := range []bool{false, true} {
		want := net.PacketConn(basic)
		if enabled {
			want = fast
		}
		if got := internet.QUICPacketConn(masked, enabled); got != want {
			t.Fatalf("masked mode %t: got %T", enabled, got)
		}
		if got := internet.QUICPacketConn(basic, enabled); got != basic {
			t.Fatal("plain socket was replaced")
		}
	}
}
