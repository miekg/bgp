package bgp

import (
	"encoding/binary"
	"fmt"
)

// Path Attributes
type PathAttr interface {
	Len() int                   // Len returns the length of the path attribute in bytes when in wire format.
	Pack([]byte) (int, error)   // Pack converts the path attribute to wire format.
	Unpack([]byte) (int, error) // Unpack converts the path attribute from wire format.
}

// Path attribute header flags.
const (
	FlagOptional   = 1 << 8
	FlagTransitive = 1 << 7
	FlagPartial    = 1 << 6
	FlagLength     = 1 << 5
)

// PathHeader is the header each of the path attributes have in common.
type PathHeader struct {
	Flags  uint8
	Code   uint8
	Length uint16
}

// Len returns the number of bytes we should use for the length by
// checking the FlagLength bit and adding the two bytes for Flags and Code.
func (p *PathHeader) Len() int {
	if p.Flags&FlagLength == FlagLength {
		return 2 + 2
	}
	return 1 + 2
}

func (p *PathHeader) Pack(buf []byte) (int, error) {
	buf[0] = p.Flags
	buf[1] = p.Code
	if p.Flags&FlagLength == FlagLength {
		binary.BigEndian.PutUint16(buf[2:], uint16(p.Length))
		return 4, nil
	}
	buf[2] = uint8(p.Length)
	return 3, nil
}

func (p *PathHeader) Unpack(buf []byte) (int, error) {
	p.Flags = buf[0]
	p.Code = buf[1]
	if p.Flags&FlagLength == FlagLength {
		p.Length = binary.BigEndian.Uint16(buf[2:])
		return 4, nil
	}
	p.Length = uint16(buf[2])
	return 3, nil
}

// Community implements RFC 1997 COMMUNITIES path attribute.
type Community struct {
	*PathHeader
	Value []uint32
}

func (p *Community) Len() int { return p.PathHeader.Len() + 4*len(p.Value) }

func (p *Community) Pack(buf []byte) (int, error) {
	if len(buf) < p.Len() {
		return 0, fmt.Errorf("buffer size too small")
	}
	offset, err := p.PathHeader.Pack(buf)
	if err != nil {
		return offset, err
	}
	for _, v := range p.Value {
		binary.BigEndian.PutUint32(buf[offset:], v)
		offset += 4
	}
	return offset, nil
}

func (p *Community) Unpack(buf []byte) (int, error) {
	offset, err := p.PathHeader.Unpack(buf)
	if err != nil {
		return offset, err
	}
	if len(buf) < p.Len() {
		return 0, fmt.Errorf("buffer size too small")
	}
	p.Value = make([]uint32, 0)
	for offset < p.Len() {
		p.Value = append(p.Value, binary.BigEndian.Uint32(buf[offset:]))
		offset += 4
	}
	return offset, nil
}

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
	AS     []uint32 // The AS numbers as 32 bit entities.
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

	AS_TRANS = 23456
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
