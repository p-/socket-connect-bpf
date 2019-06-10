package conv
import (
	"net"
	"testing"
)

func TestIpConversion(t *testing.T) {
    got := ToIP(251789322)
    if !got.Equal(net.ParseIP("10.0.2.15")) {
        t.Errorf("ToIP(251789322) = %s; want 10.0.2.15", got)
    }
}
