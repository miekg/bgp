package bgp

import "net"

// The differerent type of messages.
const (
	_ = iota
	TypeOpen
	TypeUpdate
	TypeNotification
	TypeKeepalive
	TypeRouteRefresh // See RFC 2918
)

// Heeader is the fixed-side header for each BGP message. See
// RFC 4271, section 4.1
type Header struct {
	Marker [16]byte // 16 octect field, MUST be all ones.
	Length uint16
	Type   uint8
}

type LengthPrefix struct {
	Length uint8 // Length in bits of Prefix.
	Prefix net.IP
}

type PathAttribute struct {
	Flags  uint8
	Code   uint8
	Length uint16 // If ExtendedLength is set this uses all 16 bits, otherwise we use 8
	Value  []byte
}

type Parameter struct {
	Type   uint8
	Length uint8
	Value  []byte
}

// OPEN holds the information used in the OPEN message format. RFC 4271, Section 4.2.
type OPEN struct {
	Header
	Version            uint8
	MyAutonomousSystem uint16
	HoldTime           uint16
	BGPIdentifier      net.IP // Must always be a v4 address
	ParametersLength   uint8
	Parameters         *[]Parameter
}

// UPDATE holds the information used in the UPDATE message format. RFC 4271, section 4.3
type UPDATE struct {
	WithdrawnRoutesLength               uint16
	WithdrawnRoutes                     []*LengthPrefix
	PathAttributeLength                 uint16
	PathAttributes                      []*PathAttribute
	NetworkLayerReachabilityInformation []*LengthPrefix
}
