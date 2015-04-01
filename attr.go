package bgp

// Path Attributes
type PathAttr interface {
	Len() int
	Header() *PathHeader
}

// Path attribute flags.
const (
	FlagOptional   = 1 << 8
	FlagTransitive = 1 << 7
	FlagPartial    = 1 << 6
	FlagLength     = 1 << 5
)

// PathHeader is the header each of the path attributes have
// in common.
type PathHeader struct {
	Flags uint8
	Code  uint8
}

func (*p PathHeader) Flags() uint8 {
	return p.Flags
}

func (*p PathHeader) Code() uint8 {
	return p.Code
}

// Communites implements RFC 1997 COMMUNITIES path attribute.
type Community struct {
	*PathHeader
	Value []uint32
}

// Origin implements the ORIGIN path attribute.
type Origin struct {
	*PathHeader
	Value uint8
}

// AsPath implements the AS_PATH path attribute.
type AsPath struct {
	*PathHeader
	Value []Path
}

// Path is used to encode the AS paths in the AsPath attribute
type Path struct {
	Type   uint8 // Either AS_SET of AS_SEQUENCE
	Length uint8 // Number of AS numbers to follow
	AS     []uint16
}

// Define the constants used for well-known path attributes in BGP.
const (
	_ = iota
	ORIGIN
	AS_PATH
	NEXT_HOP
	MULTI_EXIT_DISC
	LOCAL_PREF
	ATOMIC_AGGREGATE
	AGGREGATOR
	COMMUNITIES
)

// Values used int the different path attributes.
const (
	// ORIGIN
	IGP        = 0
	EGP        = 1
	INCOMPLETE = 2

	// AS_PATH
	AS_SET      = 1
	AS_SEQUENCE = 2

	// COMMUNITIES Values
	NO_EXPORT           = uint32(0xFFFFFF01)
	NO_ADVERTISE        = uint32(0xFFFFFF02)
	NO_EXPORT_SUBCONFED = uint32(0xFFFFFF03)
)

// Attr is used in the UPDATE message to set the path attribute(s).
type Attr struct {
	Flags uint8
	Code  uint8
	Value []byte
}

func (p *Attr) len() int {
	if p.Flags&FlagLength == FlagLength {
		return 2 + 2 + len(p.Value)
	}
	return 2 + 1 + len(p.Value)
}
