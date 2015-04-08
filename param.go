package bgp

import "encoding/binary"

// Parameter is used in the Open message to negotiate options.
type Parameter struct {
	Type uint8
	data []TLV
}

func (p *Parameter) Append(t int, v TLV) {
	p.Type = uint8(t)
	p.data = append(p.data, v)
}

func (p *Parameter) Bytes() []byte {
	buf := []byte{}
	for _, d := range p.data {
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
	switch p.Type {
	case CAP:
		c := &Capability{}

		i := 2
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
	CAP_MULTI_PROTOCOL
	CAP_ROUTE_REFRESH
	CAP_ROUTE_FILTERING
	CAP_MULTIPLE_ROUTES
	CAP_EXTENDED_NEXTHOP

	CAP_GRACEFUL_RESTART = 64
	CAP_AS4              = 65
)

type typeData struct {
	t int
	d []byte
}

type Capability struct {
	data []typeData
}

func (c *Capability) Append(t int, v ...interface{}) error {
	switch t {
	case CAP_MULTI_PROTOCOL:
		if len(v) != 2 {
			return nil
		}
		d := make([]byte, 4)
		binary.BigEndian.PutUint16(d, uint16(v[0].(int)))
		d[3] = uint8(v[1].(int))
		c.data = append(c.data, typeData{CAP_MULTI_PROTOCOL, d})
	case CAP_ROUTE_REFRESH:
		c.data = append(c.data, typeData{CAP_ROUTE_REFRESH, nil})
	case CAP_AS4:
		d := make([]byte, 4)
		binary.BigEndian.PutUint32(d, uint32(v[0].(int)))
		c.data = append(c.data, typeData{CAP_AS4, d})
	default:
		// unknown capability
	}
	return nil
}

func (c *Capability) Bytes() []byte {
	buf := make([]byte, 0)
	for _, d := range c.data {
		switch d.t {
		case CAP_MULTI_PROTOCOL:
			buf = append(buf, CAP_MULTI_PROTOCOL)
			buf = append(buf, 4) // length
			buf = append(buf, d.d...)
		case CAP_ROUTE_REFRESH:
			buf = append(buf, CAP_ROUTE_REFRESH)
			buf = append(buf, 0) // length
			// no data
		case CAP_AS4:
			buf = append(buf, CAP_AS4)
			buf = append(buf, 4) // length
			buf = append(buf, d.d...)
		}
	}
	return buf
}

func (c *Capability) SetBytes(buf []byte) (int, error) {
	i := 0
	for i < len(buf) {
		switch buf[i] {
		// i+1 will overflow: TODO
		case CAP_MULTI_PROTOCOL:
			if buf[i+1] != 4 {
				println("bgp: CAP_MULTI_PROTOCOL not 4 bytes", int(buf[i+1]))
				return i, errBuf
			}
			afi := int(binary.BigEndian.Uint16(buf[i+2:]))
			safi := int((buf[i+5]))
			c.Append(CAP_MULTI_PROTOCOL, afi, safi)
			i += 6
		case CAP_ROUTE_REFRESH:
			if buf[i+1] != 0 {
				println("bgp: CAP_ROUTE_REFRESH not 0 bytes", int(buf[i+1]))
				return i, errBuf
			}
			c.Append(CAP_ROUTE_REFRESH, nil)
			i += 2
		case CAP_AS4:
			if len(buf[i:]) < 6 {
				return i, errBuf
			}
			if buf[i+1] != 4 {
				println("bgp: CAP_AS4 not 4 bytes")
				return i, errBuf
			}
			// We going from binary->uint32->binary, we might not be the best way
			v := binary.BigEndian.Uint32(buf[i+2 : i+6])
			c.Append(CAP_AS4, int(v))
			i += 7
		default:
			println("bgp: unknown capability", buf[i])
			i++
		}
	}
	return i, nil
}
