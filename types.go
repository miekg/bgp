package bgp

import (
	"net"
)

const (
	_ = iota

	// The different types of messages.
	Open
	Update
	Notification
	Keepalive
	RouteRefresh // See RFC 2918

	headerLen = 19

	MaxSize   = 4096 // Maximum size of a BGP message.
	Version   = 4    // Current defined version of BGP.
)

// TODO(miek): finalize this
type Message interface {
	pack([]byte) (int, error)
	unpack([]byte) (int, error)
	//	String() string
	Len() int
}

// Header is the fixed-side header for each BGP message. See
// RFC 4271, section 4.1. The marker is omitted.
type Header struct {
	Length uint16
	Type   uint8
}

type Prefix net.IPNet

// Size returns the length of the mask in bits.
func (p *Prefix) Size() int {
	_, bits := p.Mask.Size()
	return bits
}

// len returns the length of prefix in bytes.
func (p *Prefix) len() int { return 1 + len(p.IP) }

// Parameter is used in the OPEN message to negotiate options.
type Parameter struct {
	Type  uint8
	Value []byte
}

func (p *Parameter) len() int { return 2 + len(p.Value) }

// OPEN holds the information used in the OPEN message format. RFC 4271, Section 4.2.
type OPEN struct {
	*Header
	Version       uint8
	MyAS          uint16 // AS_TRANS usaully.
	HoldTime      uint16
	BGPIdentifier net.IP // Must always be a 4 bytes.
	Parameters    []Parameter
}

// Len returns the length of the entire OPEN message.
func (m *OPEN) Len() int {
	l := 0
	for _, p := range m.Parameters {
		l += p.len()
	}
	return headerLen + 10 + l
}

// UPDATE holds the information used in the UPDATE message format. RFC 4271, section 4.3
type UPDATE struct {
	*Header
	WithdrawnRoutes  []Prefix
	PathAttrs        []PathAttr
	ReachabilityInfo []Prefix
}

func (m *UPDATE) Len() int {
	l := 0
	for _, p := range m.WithdrawnRoutes {
		l += p.len()
	}
	for _, p := range m.PathAttrs {
		l += p.Len()
	}
	for _, p := range m.ReachabilityInfo {
		l += p.len()
	}

	return headerLen + 4 + l
}

// KEEPALIVE holds only the header and is used for keep alive pings.
type KEEPALIVE struct {
	*Header
}

func (m *KEEPALIVE) Len() int { return headerLen }

// NOTIFICATION holds an error. The TCP connection is closed after sending it.
type NOTIFICATION struct {
	*Header
	ErrorCode    uint8
	ErrorSubcode uint8
	Data         []byte
}

func (m *NOTIFICATION) Len() int { return headerLen + 2 + len(m.Data) }
