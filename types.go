package bgp

import "net"

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
	Type uint8
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

// Len returns the length of the entire OPEN message.
// When called is also sets the length in m.Length.
func (m *OPEN) Len() int {
	l := 0
	for _, p := range m.Parameters {
		l += p.len()
	}
	m.Header.Length = headerLen + 10 + uint16(l)
	return int(m.Header.Length)
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

func (m *UPDATE) Len() int {
	m.Header.Length = headerLen // + more shit
	return int(m.Header.Length)
}

// KEEPALIVE holds only the header and is used for keep alive pings.
type KEEPALIVE struct {
	*Header
}

func (m *KEEPALIVE) Len() int {
	m.Header.Length = headerLen
	return int(m.Header.Length)
}

// NOTIFICATION holds an error. The TCP connection is closed after sending it.
type NOTIFICATION struct {
	*Header
	ErrorCode    uint8
	ErrorSubcode uint8
	Data         []byte
}

func (m *NOTIFICATION) Len() int {
	m.Header.Length = headerLen + 2 + uint16(len(m.Data))
	return int(m.Header.Length)
}
