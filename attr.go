package bgp

// Path attributes, as used in the Update message.

import (
	"encoding/binary"
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

// TLV (Type-Length-Value) is a typical BGP construction that is used in messages.
type TLV interface {
	Type() int                    // Type returns the type of the TLV.
	SetType(t int)                // SetType sets the type of the TLV.
	Len() int                     // Len returns the length of the TLV bytes when in wire format.
	Bytes() []byte                // Bytes return the bytes of the value in wire format.
	SetBytes([]byte) (int, error) // SetBytes sets the value of the TLV, the bytes must be in network order.
}

// Path attribute header flags.
const (
	FlagOptional   = 1 << 8
	FlagTransitive = 1 << 7
	FlagPartial    = 1 << 6
	FlagLength     = 1 << 5
)

// pathHeader is the header each of the path attributes have in common.
type pathHeader struct {
	Flags  uint8
	Code   uint8
	Length uint16 // Length is either stored with 8 or 16 bits.
}

func (p *pathHeader) Type() uint8 { return p.Code }

func (p *pathHeader) Len() int {
	if p.Flags&FlagLength == FlagLength {
		return 2 + 2
	}
	return 1 + 2
}

func (p *pathHeader) Bytes(buf []byte) int {
	buf[0] = p.Flags
	buf[1] = p.Code
	if p.Flags&FlagLength == FlagLength {
		binary.BigEndian.PutUint16(buf[2:], uint16(p.Length))
		return 4
	}
	buf[2] = uint8(p.Length)
	return 3
}

// Allow value to write to buf bytes, which should be 4 octets max.
func (p *pathHeader) SetBytes(buf []byte) int {
	p.Flags = buf[0]
	p.Code = buf[1]
	if p.Flags&FlagLength == FlagLength {
		p.Length = binary.BigEndian.Uint16(buf[2:])
		return 4
	}
	p.Length = uint16(buf[2])
	return 3
}

// Community implements RFC 1997 COMMUNITIES path attribute.
type Community struct {
	*pathHeader
	Value []uint32
}

func (p *Community) Type() int { return p.Type() }
func (p *Community) Len() int  { return p.pathHeader.Len() + 4*len(p.Value) }

func (p *Community) Bytes() []byte {
	buf := make([]byte, p.Len())
	offset := p.pathHeader.Bytes(buf)
	for _, v := range p.Value {
		binary.BigEndian.PutUint32(buf[offset:], v)
		offset += 4
	}
	return buf
}

func (p *Community) SetBytes(buf []byte) (int, error) {
	offset := p.pathHeader.SetBytes(buf)

	p.Value = make([]uint32, 0)
	for offset < int(p.Length) {
		p.Value = append(p.Value, binary.BigEndian.Uint32(buf[offset:]))
		offset += 4
	}
	return offset, nil
}

// Origin implements the ORIGIN path attribute.
type Origin struct {
	*pathHeader
	Value uint8
}

func (p *Origin) Type() int { return p.Type() }
func (p *Origin) Len() int  { return p.pathHeader.Len() + 1 }

func (p *Origin) Bytes() []byte {
	buf := make([]byte, p.Len())
	offset := p.pathHeader.Bytes(buf)
	buf[offset] = p.Value
	return buf
}

func (p *Origin) SetBytes(buf []byte) (int, error) {
	offset := p.pathHeader.SetBytes(buf)
	p.Value = buf[offset]
	return offset + 1, nil
}

// AsPath implements the AS_PATH path attribute.
type AsPath struct {
	*pathHeader
	Value []Path
}

func (p *AsPath) Type() int { return p.Type() }

func (p *AsPath) Len() int {
	l := p.pathHeader.Len()
	for _, v := range p.Value {
		l += v.len()
	}
	return l
}

func (p *AsPath) Bytes() []byte {
	return nil
}

func (p *AsPath) SetBytes(buf []byte) (int, error) {
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
	*pathHeader
	Value net.IP
}

func (p *NextHop) Len() int { return p.pathHeader.Len() + len(p.Value) }

func (p *NextHop) Pack(buf []byte) (int, error) {
	return 0, nil
}

func (p *NextHop) Unpack(buf []byte) (int, error) {
	return 0, nil
}
