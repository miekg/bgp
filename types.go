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

	headerLen = 19
	MaxSize   = 4096
	MinSize   = 27 // TODO(miek): check
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

func (pa *PathAttribute) len() int {
	if pa.Flags & 0x01 == 0x01 { // whatever check
		return 2 + 1 + len(pa.Value)
	}
	return 2 + 2 + len(pa.Value)
}

type Parameter struct {
	Type   uint8
	Length uint8
	Value  []byte
}

func (p *Parameter) len() int { return 2 + len(p.Value) }

// OPEN holds the information used in the OPEN message format. RFC 4271, Section 4.2.
type OPEN struct {
	*Header
	Version            uint8
	MyAutonomousSystem uint16
	HoldTime           uint16
	BGPIdentifier      net.IP // Must always be a v4 address
	ParametersLength   uint8
	Parameters         *[]Parameter
}

// len returns the length of the entire message.
func (m *OPEN) len() int {
	// todo I calculate the lengths of the params twice
	// set paramlen as well.:w
	`
	return headerLen + 10 // + len(params) 
}

// UPDATE holds the information used in the UPDATE message format. RFC 4271, section 4.3
type UPDATE struct {
	*Header
	WithdrawnRoutesLength               uint16
	WithdrawnRoutes                     []*LengthPrefix
	PathAttributeLength                 uint16
	PathAttributes                      []*PathAttribute
	NetworkLayerReachabilityInformation []*LengthPrefix
}
