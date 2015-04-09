package bgp

import (
	"net"
	"testing"
)

type testCase struct {
	in  []byte // buffer to parse
	n   int    // number of bytes we should have parsed
	msg Msg    // resulting message
}

var tests = []testCase{
	{
		[]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 45, 1, 4, 253, 232, 0, 240, 176, 58, 119, 54, 16, 2, 14, 1, 4, 0, 1, 0, 1, 2, 0, 65, 4, 0, 0, 253, 232},
		45,
		&Open{
			Version:       4,
			AS:            65000,
			HoldTime:      240,
			BGPIdentifier: net.ParseIP("b03a:7736::ffff:0:0"),
			//Parameters:[{Type:2 data:[0x1842e0b0]}] header:0x1842e080}

		},
	},
}

func msgCompare(t *testing.T, te Msg, a Msg) {
	switch typ := a.(type) {
	case *Open:
		te := te.(*Open)
		a := a.(*Open)
		if te.Version != a.Version {
			t.Fatalf("open version mismatch: expected %d, got %d", te.Version, a.Version)
		}
		if te.AS != a.AS {
			t.Fatalf("open as mismatch: expected %d, got %d", te.AS, a.AS)
		}
		if te.HoldTime != a.HoldTime {
			t.Fatalf("open holdtime mismatch: expected %d, got %d", te.HoldTime, a.HoldTime)
		}
		t.Logf("%s\n", a.BGPIdentifier)
		t.Logf("%s\n", te.BGPIdentifier)
	default:
		t.Fatalf("unknown message type %T", typ)
	}
}

func TestMsgsetBytes(t *testing.T) {
	for _, te := range tests {
		m, n, e := setBytes(te.in)
		if e != nil {
			t.Fatalf("setBytes() failed: %s", e)
		}
		if n != te.n {
			t.Fatalf("parsed octets: expected %d, got %d", te.n, n)
		}
		msgCompare(t, te.msg, m) // will Fatalf for us.
	}
}
