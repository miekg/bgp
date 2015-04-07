package bgp

// Path attributes as used in the Update message.

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

// TLV is a Type-Length-Value that is used in all on-the-wire messages.
type TLV interface {
	// Code returns the type of the TLV.
	Code() uint8
	// Bytes return the bytes of the value in wire format.
	Bytes() []byte
	// SetBytes sets the value of the TLV, the bytes must be in network order.
	// It returns a new offset in the bytes slice.
	SetBytes([]byte) (int, error)
}

// Path attribute header flags.
const (
	FlagOptional   = 1 << 8
	FlagTransitive = 1 << 7
	FlagPartial    = 1 << 6
	FlagLength     = 1 << 5
)

// AttrHeader is the header each of the path attributes have in common.
type AttrHeader struct {
	Flags  uint8
	Code   uint8
	Length uint16 // Length is either stored with 8 or 16 bits.
}

func (p *AttrHeader) Len() int {
	if p.Flags&FlagLength == FlagLength {
		return 2 + 2
	}
	return 1 + 2
}

func (p *AttrHeader) Bytes() []byte {
	buf := make([]byte, p.Len())
	buf[0] = p.Flags
	buf[1] = p.Code
	buf[2] = uint8(p.Length)
	if len(buf) == 4 {
		binary.BigEndian.PutUint16(buf[2:], uint16(p.Length))
	}
	return buf
}

func (p *AttrHeader) SetBytes(buf []byte) (int, error) {
	if len(buf) < 3 {
		return 0, errBuf
	}
	p.Flags = buf[0]
	p.Code = buf[1]
	if p.Flags&FlagLength == FlagLength {
		if len(buf) < 3 {
			return 2, errBuf
		}
		p.Length = binary.BigEndian.Uint16(buf[2:])
		return 4, nil
	}
	p.Length = uint16(buf[2])
	return 3, nil
}

// Community implements RFC 1997 COMMUNITIES path attribute.
type Community struct {
	*AttrHeader
	Communities []uint32
}

func (p *Community) Len() int { return p.AttrHeader.Len() + 4*len(p.Communities) }

func (p *Community) Bytes() []byte {
	header := p.AttrHeader.Bytes()

	buf := make([]byte, p.Len()-p.AttrHeader.Len())
	offset := 0
	for _, v := range p.Communities {
		binary.BigEndian.PutUint32(buf[offset:], v)
		offset += 4
	}
	return append(header, buf...)
}

func (p *Community) SetBytes(buf []byte) (int, error) {
	offset, err := p.AttrHeader.SetBytes(buf)
	if err != nil {
		return offset, err
	}

	p.Communities = make([]uint32, 0)
	for offset < int(p.Length) {
		p.Communities = append(p.Communities, binary.BigEndian.Uint32(buf[offset:]))
		offset += 4
	}
	return offset, nil
}

// Origin implements the ORIGIN path attribute.
type Origin struct {
	*AttrHeader
	Origin uint8
}

func (p *Origin) Len() int { return p.AttrHeader.Len() + 1 }

func (p *Origin) Bytes() []byte {
	header := p.AttrHeader.Bytes()
	return append(header, byte(p.Origin))
}

func (p *Origin) SetBytes(buf []byte) (int, error) {
	offset, err := p.AttrHeader.SetBytes(buf)
	if err != nil {
		return offset, err
	}
	p.Origin = buf[offset]
	return offset + 1, nil
}

// AsPath implements the AS_PATH path attribute.
type AsPath struct {
	*AttrHeader
	Paths []Path
}

func (p *AsPath) Len() int {
	l := p.AttrHeader.Len()
	for _, v := range p.Paths {
		l += v.Len()
	}
	return l
}

func (p *AsPath) Bytes() []byte {
	buf := p.AttrHeader.Bytes()
	for _, p := range p.Paths {
		buf = append(buf, p.Bytes()...)
	}
	return buf
}

func (p *AsPath) SetBytes(buf []byte) (int, error) {
	offset, err := p.AttrHeader.SetBytes(buf)
	if err != nil {
		return offset, err
	}
	return offset, err
}

// Path is used to encode the AS paths in the AsPath attribute
type Path struct {
	Type uint8    // Either AS_SET of AS_SEQUENCE.
	AS   []uint32 // The AS numbers as 32 bit entities.
}

func (p *Path) Len() int { return 2 + 4*len(p.AS) }

func (p *Path) Bytes() []byte {
	buf := make([]byte, p.Len())
	buf[0] = p.Type
	buf[1] = uint8(len(p.AS))

	offset := 2

	for _, a := range p.AS {
		binary.BigEndian.PutUint32(buf[offset:], a)
		offset += 4
	}
	return buf
}

func (p *Path) SetBytes(buf []byte) (int, error) {
	if len(buf) < 2 {
		return 0, errBuf
	}

	p.Type = buf[0]
	l := int(buf[1])

	if len(buf) < 2+4*l {
		return 0, errBuf
	}

	offset := 2
	p.AS = make([]uint32, 0)
	for offset < 2+4*l {
		p.AS = append(p.AS, binary.BigEndian.Uint32(buf[offset:]))
		offset += 4
	}
	return offset, nil
}

type NextHop struct {
	*AttrHeader
	NextHop net.IP
}

func (p *NextHop) Len() int { return p.AttrHeader.Len() + len(p.NextHop) }

func (p *NextHop) Bytes() []byte {
	return nil
}

func (p *NextHop) SetBytes(buf []byte) (int, error) {
	return 0, nil
}
