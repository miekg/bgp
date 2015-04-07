package bgp

import "encoding/binary"

// Parameter is used in the Open message to negotiate options.
type Parameter struct {
	Type    uint8
	Data []TLV
}

func (p *Parameter) Code() int { return int(p.Type) }

func (p *Parameter) Append(t int, v TLV) {
	p.Type = uint8(t)
	p.Data = append(p.Data, v)
}

func (p *Parameter) Bytes() []byte {
	buf := []byte{}
	for _, d := range p.Data {
		buf = append(buf, d.Bytes()...)
	}
	return append([]byte{p.Type, byte(len(buf))}, buf...)
}

func (p *Parameter) SetBytes(buf []byte) (int, error) {
	if len(buf) < 3 {
		return 0, errBuf
	}
	p.Type = buf[0]
	length := int(buf[1])
	if len(buf) < length {
		return 0, errBuf
	}
	buf = buf[2:]
	switch p.Type {
	case CAP:
		c := &Capability{}

		i := 0
		for i < length {
			n, e := c.SetBytes(buf[i:])
			if e != nil {
				return i + n, e
			}
			i += n
		}
		p.Append(CAP, c)
	default:
		println("bgp: unknown type", p.Type)
	}
	return length + 2, nil // Add 2 for the 2 byte header
}

const (
	CAP = 2
)

// The different capabilities
const (
	_ = iota
	CAP_MULTI_PROTOCOl
	CAP_ROUTE_REFRESH
	CAP_ROUTE_FILTERING
	CAP_MULTIPLE_ROUTES
	CAP_EXTENDED_NEXTHOP

	CAP_GRACEFUL_RESTART = 64
	CAP_AS4              = 65
)

type typeData struct {
	t int
	d interface{}
}

type Capability struct {
	data []typeData
}

func (c *Capability) Append(t int, v interface{}) {
	switch t {
	case CAP_AS4:
		// Breaks when type case fails.
		c.data = append(c.data, typeData{t, v.(int)})
	default:
		// unknown capability
	}
}

func (c *Capability) Code() uint8 { return CAP }

func (c *Capability) Bytes() []byte {
	buf := make([]byte, 0)
	for _, d := range c.data {
		switch d.t {
		case CAP_AS4:
			b := make([]byte, 6)
			b[0] = uint8(d.t)
			b[1] = 4
			binary.BigEndian.PutUint32(b[2:], uint32(d.d.(int)))
			buf = append(buf, b...)
		}
	}
	return buf
}

func (c *Capability) SetBytes(buf []byte) (int, error) {
	i := 0
	for i < len(buf) {
		switch buf[i] {
		case CAP_AS4:
			if len(buf[i:]) < 6 {
				return i, errBuf
			}
			if buf[i+1] != 4 {
				println("bgp: AS4 not 4 bytes")
				return i, errBuf
			}
			v := binary.BigEndian.Uint32(buf[2:6])
			c.Append(CAP_AS4, v)
			i += 6
		default:
			println("bgp: unknown capability", buf[i])
		}
	}
	return i, nil
}
