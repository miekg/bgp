package bgp

import (
	"net"
)

const (
	_ = iota

	// The different types of messages.
	open
	update
	notification
	keepalive
	routerefresh // See RFC 2918

	headerLen = 19

	MaxSize = 4096 // Maximum size of a BGP message.
	Version = 4    // Current defined version of BGP.
)

// TLV is a Type-Length-Value that is used in all on-the-wire messages.
type TLV interface {
	// Bytes return the bytes of the value in wire format.
	Bytes() []byte
	// SetBytes sets the value of the TLV, the bytes must be in network order.
	// It returns a new offset in the bytes slice.
	SetBytes([]byte) (int, error)

	// maybe add Append here as well. Append(t int, v ...interface{}) error
}

// Message is a BGP message.
type Message interface {
	bytes() []byte
	setBytes([]byte) (int, error)
}

// Open holds the information used in the OPEN message format. RFC 4271, Section 4.2.
type Open struct {
	// Version MUST be 4. If it is zero, 4 will be used when converting to wire format.
	Version uint8
	// AS should be AS_TRANS when using 32 bit ASN. If this is 0, AS_TRANS will be
	// substitued when converting to wire format.
	AS       uint16
	HoldTime uint16
	// BGPIdentifier must always be 4 bytes. It will be truncated to 4 bytes
	// when the Open messgae is converted to wire format.
	BGPIdentifier net.IP
	Parameters    []Parameter

	*header
}

// Update holds the information used in the UPDATE message format. RFC 4271, section 4.3
type Update struct {
	WithdrawnRoutes  []Prefix
	Attributes       []Attribute
	ReachabilityInfo []Prefix

	*header
}

// Keepalive holds only the header and is used for keep alive pings.
type Keepalive struct {
	*header
}

// Notification holds an error. The TCP connection is closed after sending it.
type Notification struct {
	ErrorCode    uint8
	ErrorSubcode uint8
	Data         []byte
	*header
}
