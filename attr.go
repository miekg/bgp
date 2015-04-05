package bgp

// Path attributes, as used in the Update message.

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Define the types used for well-known path attributes in an Update message.
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

// Values used in the well-known path attributes.
const (
	// ORIGIN
	IGP        = 0
	EGP        = 1
	INCOMPLETE = 2

	// AS_PATH
	AS_SET      = 1
	AS_SEQUENCE = 2

	// COMMUNITIES
	NO_EXPORT           = uint32(0xFFFFFF01)
	NO_ADVERTISE        = uint32(0xFFFFFF02)
	NO_EXPORT_SUBCONFED = uint32(0xFFFFFF03)
)

const AS_TRANS = 23456

// PathAttr is the interface all path attributes should implement.
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
	if len(buf) < int(p.Length) {
		return 0, fmt.Errorf("buffer size too small")
	}
	p.Value = make([]uint32, 0)
	for offset < int(p.Length) {
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

func (p *Origin) Pack(buf []byte) (int, error) {
	if len(buf) < p.Len() {
		return 0, fmt.Errorf("buffer size too small")
	}
	offset, err := p.PathHeader.Pack(buf)
	if err != nil {
		return offset, err
	}
	buf[offset] = p.Value
	return offset + 1, nil
}

func (p *Origin) Unpack(buf []byte) (int, error) {
	offset, err := p.PathHeader.Unpack(buf)
	if err != nil {
		return offset, err
	}
	if len(buf) < int(p.Length) {
		return 0, fmt.Errorf("buffer size too small")
	}
	p.Value = buf[offset]
	return offset + 1, nil
}

// AsPath implements the AS_PATH path attribute.
type AsPath struct {
	*PathHeader
	Value []Path
}

func (p *AsPath) Len() int {
	l := p.PathHeader.Len()
	for _, v := range p.Value {
		l += v.len()
	}
	return l
}

func (p *AsPath) Pack(buf []byte) (int, error) {
	return 0, nil
}

func (p *AsPath) Unpack(buf []byte) (int, error) {
	return 0, nil
}

// Path is used to encode the AS paths in the AsPath attribute
type Path struct {
	Type uint8    // Either AS_SET of AS_SEQUENCE.
	AS   []uint32 // The AS numbers as 32 bit entities.
}

func (p *Path) len() int { return 2 + 4*len(p.AS) }

func (p *Path) pack(buf []byte) (int, error) {
	buf[0] = p.Type
	buf[1] = uint8(len(p.AS))

	offset := 2

	for _, a := range p.AS {
		binary.BigEndian.PutUint32(buf[offset:], a)
		offset += 4
	}
	return offset, nil
}

func (p *Path) unpack(buf []byte) (int, error) {
	p.Type = buf[0]

	l := int(buf[1])
	// TODO(miek): length checks here

	offset := 2
	p.AS = make([]uint32, 0)
	for offset < 2+4*l {
		p.AS = append(p.AS, binary.BigEndian.Uint32(buf[offset:]))
		offset += 4
	}
	return offset, nil
}

type NextHop struct {
	*PathHeader
	Value net.IP
}

func (p *NextHop) Len() int { return p.PathHeader.Len() + len(p.Value) }

func (p *NextHop) Pack(buf []byte) (int, error) {
	return 0, nil
}

func (p *NextHop) Unpack(buf []byte) (int, error) {
	return 0, nil
}
