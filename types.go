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
	Bytes() []byte
	SetBytes([]byte) (int, error)
}

// Open holds the information used in the OPEN message format. RFC 4271, Section 4.2.
type Open struct {
	*header
	Version       uint8
	MyAS          uint16 // AS_TRANS usaully.
	HoldTime      uint16
	BGPIdentifier net.IP // Must always be a 4 bytes.
	Parameters    []Parameter
}

// Update holds the information used in the UPDATE message format. RFC 4271, section 4.3
type Update struct {
	*header
	WithdrawnRoutes  []Prefix
	Attrs            []TLV
	ReachabilityInfo []Prefix
}

// Keepalive holds only the header and is used for keep alive pings.
type Keepalive struct {
	*header
}

// Notification holds an error. The TCP connection is closed after sending it.
type Notification struct {
	*header
	ErrorCode    uint8
	ErrorSubcode uint8
	Data         []byte
}
