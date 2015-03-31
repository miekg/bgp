package bgp

import (
	"net"
)

// The differerent type of messages.
const (
	_ = iota
	typeOpen
	typeUpdate
	typeNotification
	typeKeepalive
	typeRouteRefresh // See RFC 2918

	headerLen = 19
	MaxSize   = 4096
	Version   = 4
)

type Message interface {
	pack([]byte) (int, error)
	unpack([]byte) (int, error)
	//	String() string
	Len() int
}

// Heeader is the fixed-side header for each BGP message. See
// RFC 4271, section 4.1
type Header struct {
	Marker [16]byte // MUST be all ones...
	Length uint16
	Type   uint8
}

func newHeader(typ int) *Header { return &Header{[16]byte{}, 0, uint8(typ)} }

type LengthPrefix struct {
	Length uint8 // Length in bits of Prefix.
	Prefix net.IP
}

// PathAttr Flags.
const (
	FlagOptional   = 1 << 8
	FlagTransitive = 1 << 7
	FlagPartial    = 1 << 6
	FlagLength     = 1 << 5
)

// PathAttr Codes.
const (
	_ = iota
	Origin
	ASPath
	NextHop
	MultiExitDisc
	LocalPref
	AtomicAggregate
	Aggregator
)

type PathAttr struct {
	Flags uint8
	Code  uint8
	//If Flag.Length is set length can use 16 bits, otherwise we use 8 bits.
	// Length uint8 or uint16
	Value []byte
}

func (pa *PathAttr) len() int {
	if pa.Flags&FlagLength == FlagLength {
		return 2 + 2 + len(pa.Value)
	}
	return 2 + 1 + len(pa.Value)
}

type Parameter struct {
	Type  uint8

	// parm length removed as it is len(Value).

	Value []byte
}

func (p *Parameter) len() int { return 2 + len(p.Value) }

// OPEN holds the information used in the OPEN message format. RFC 4271, Section 4.2.
type OPEN struct {
	*Header
	Version       uint8
	MyAS          uint16
	HoldTime      uint16
	BGPIdentifier net.IP // Must always be a v4 address
	Parameters    []Parameter
}

// NewOPEN returns an initialized OPEN message.
func NewOPEN(MyAS, HoldTime uint16, BGPIdentifier net.IP, Parameters []Parameter) *OPEN {

	return &OPEN{Header: newHeader(typeOpen), Version: Version, MyAS: MyAS,
		HoldTime: HoldTime, BGPIdentifier: BGPIdentifier.To4(), Parameters: Parameters}
}

// Len returns the length of the entire OPEN message.
// When called is also sets the length in m.Length.
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
	WithdrawnRoutesLength uint16 // make implicit
	WithdrawnRoutes       []LengthPrefix
	PathAttrsLength       uint16 // make implicit
	PathAttrs             []PathAttr
	ReachabilityInfo      []LengthPrefix
}

// TODO(miek): incomplete
func (m *UPDATE) Len() int { return headerLen }

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
