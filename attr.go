package bgp

// Path Attributes
type PathAttr interface {
	Len() int // Len returns the length of the path attribute in bytes when in wire format.
	Pack([]byte) (int, error)   // Pack converts the path attribute to wire format.
	Unpack([]byte) (int, error) // Unpack converts the path attribute from wire format.
}

// Path attribute flags.
const (
	FlagOptional   = 1 << 8
	FlagTransitive = 1 << 7
	FlagPartial    = 1 << 6
	FlagLength     = 1 << 5
)

// PathHeader is the header each of the path attributes have in common.
// Note that the length is used in the wire format, but not specified here,
// because it is implicitly encoding in the length of the Value.
type PathHeader struct {
	Flags uint8
	Code  uint8
}

// ExtendedLength returns the number of bytes we should use
// for the length by checking the FlagLength bit and adding
// the two bytes for Flags and Code.
func (p *PathHeader) Len() int {
	if p.Flags&FlagLength == FlagLength {
		return 2 + 2
	}
	return 1 + 2
}

// Communites implements RFC 1997 COMMUNITIES path attribute.
type Community struct {
	*PathHeader
	Value []uint32
}

func (p *Community) Len() int { return p.PathHeader.Len() + 4*len(p.Value) }

// Origin implements the ORIGIN path attribute.
type Origin struct {
	*PathHeader
	Value uint8
}

func (p *Origin) Len() int { return p.PathHeader.Len() + 1 }

// AsPath implements the AS_PATH path attribute.
type AsPath struct {
	*PathHeader
	Value []Path
}

// Path is used to encode the AS paths in the AsPath attribute
type Path struct {
	Type   uint8    // Either AS_SET of AS_SEQUENCE.
	Length uint8    // Number of AS numbers to follow.
	AS     []uint16 // The AS numbers.
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
