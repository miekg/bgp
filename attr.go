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

// Path attribute header flags.
const (
	FlagOptional   = 1 << 8
	FlagTransitive = 1 << 7
	FlagPartial    = 1 << 6
	FlagLength     = 1 << 5
)

// Attribute is a path attribute as used in the Update message.
type Attribute struct {
	Flags  uint8
	Code   uint8
	Length uint16
	//	if p.Flags&FlagLength == FlagLength {
	data []TLV

	// maybe put the data in a map based on Code. So Cel
}

func (p *Attribute) Append(t int, v TLV) error {
	p.Code = uint8(t)
	p.data = append(p.data, v)
	return nil
}

func (p *Attribute) Bytes() []byte {
	buf := []byte{}
	for _, d := range p.data {
		buf = append(buf, d.Bytes()...)
	}
	header := make([]byte, 4)
	header[0] = p.Flags
	header[1] = p.Code
	if len(buf) > 65536-1 {
		header[0] |= FlagLength
		binary.BigEndian.PutUint16(header[2:], uint16(p.Length))
	} else {
		header[2] = uint8(len(buf))
		header = header[:3]
	}
	return append(header, buf...)
}

func (p *Attribute) SetBytes(buf []byte) (int, error) {
	// TODO(Miek): does not work.
	if len(buf) < 3 {
		return 0, errBuf
	}
	p.Flags = buf[0]
	p.Code = buf[1]
	if p.Flags&FlagLength == FlagLength {
		if len(buf) < 4 {
			return 2, errBuf
		}
		p.Length = binary.BigEndian.Uint16(buf[2:])
		return 4, nil
	}
	p.Length = uint16(buf[2])
	return 3, nil
}

// Origin implements the ORIGIN path attribute.
type Origin uint8

func (p *Origin) Bytes() []byte { return []byte{uint8(*p)} }
func (p *Origin) SetBytes(buf []byte) (int, error) {
	if len(buf) < 1 {
		return 0, errBuf
	}
	*p = Origin(buf[0])
	return 1, nil
}

// Community implements RFC 1997 COMMUNITIES path attribute.
type Community []uint32

func (p *Community) Bytes() []byte {
	buf := make([]byte, 4*len(*p))
	for i, v := range *p {
		binary.BigEndian.PutUint32(buf[i*4:], v)
	}
	return buf
}

func (p *Community) SetBytes(buf []byte) (int, error) {
	offset := 0
	for offset < len(buf)-4 {
		*p = append(*p, binary.BigEndian.Uint32(buf[offset:]))
		offset += 4
	}
	return offset, nil
}

// AsPath implements the AS_PATH path attribute.
type Path []AsPath

type AsPath struct {
	Type uint8    // Either AS_SET of AS_SEQUENCE.
	AS   []uint32 // The AS numbers as 32 bit entities.
}

func (p *Path) Bytes() []byte {
	var buf []byte
	for _, a := range *p {
		b := make([]byte, 2+4*len(a.AS))
		b[0] = a.Type
		b[1] = byte(len(a.AS))
		offset := 2
		for _, as := range a.AS {
			binary.BigEndian.PutUint32(b[offset:], as)
			offset += 4
		}
		buf = append(buf, b...)
	}
	return buf
}

func (p *Path) SetBytes(buf []byte) (int, error) {
	return 0, nil
}

type NextHop net.IP

func (p *NextHop) Bytes() []byte {
	return nil
}

func (p *NextHop) SetBytes(buf []byte) (int, error) {
	return 0, nil
}
