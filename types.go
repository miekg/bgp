package bgp

import (
	"net"
)

const (
	_ = iota

	// The different types of messages.
	OPEN
	UPDATE
	NOTIFICATION
	KEEPALIVE
	ROUTErEFRESH // See RFC 2918

	headerLen = 19

	MaxSize = 4096 // Maximum size of a BGP message.
	Version = 4    // Current defined version of BGP.
)

type Message interface {
	pack([]byte) (int, error)
	unpack([]byte) (int, error)
	//	String() string?
	Len() int
}

// Open holds the information used in the OPEN message format. RFC 4271, Section 4.2.
type Open struct {
	*Header
	Version       uint8
	MyAS          uint16 // AS_TRANS usaully.
	HoldTime      uint16
	BGPIdentifier net.IP // Must always be a 4 bytes.
	Parameters    []Parameter
}

// Len returns the length of the entire OPEN message.
func (m *Open) Len() int {
	l := 0
	for _, p := range m.Parameters {
		l += p.Len()
	}
	return headerLen + 10 + l
}

// Update holds the information used in the UPDATE message format. RFC 4271, section 4.3
type Update struct {
	*Header
	WithdrawnRoutes  []Prefix
	Attrs            []TLV
	ReachabilityInfo []Prefix
}

func (m *Update) Len() int {
	l := 0
	for _, p := range m.WithdrawnRoutes {
		l += p.Len()
	}
	for _, p := range m.Attrs {
		l += p.Len()
	}
	for _, p := range m.ReachabilityInfo {
		l += p.Len()
	}

	return headerLen + 4 + l
}

// Keepalive holds only the header and is used for keep alive pings.
type Keepalive struct {
	*Header
}

func (m *Keepalive) Len() int { return headerLen }

// Notification holds an error. The TCP connection is closed after sending it.
type Notification struct {
	*Header
	ErrorCode    uint8
	ErrorSubcode uint8
	Data         []byte
}

func (m *Notification) Len() int { return headerLen + 2 + len(m.Data) }
