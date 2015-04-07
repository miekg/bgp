package bgp

import "encoding/binary"

// The optional Parameters types that are defined.
const (
	CAPABILITY = 2
)

// Parameter is used in the Open message to negotiate options.
type Parameter struct {
	Type    uint8
	Options []TLV
}

func (p *Parameter) Len() int {
	l := 1
	for _, o := range p.Options {
		l += o.Len()
	}
	return l
}

func (p *Parameter) Code() int { return int(p.Type) }

func (p *Parameter) Bytes() []byte {
	buf := make([]byte, 2)
	buf[0] = p.Type

	l := 0
	for _, o := range p.Options {
		buf = append(buf, o.Bytes()...)
		l += o.Len()
	}

	buf[1] = uint8(l)
	return buf
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

	for i := 0; i < length; i++ {
		// Type, code and length
		n, e := p.Options[i].SetBytes(buf[i+2:])
		if e != nil {
			return i + 2, e
		}
		i += n
	}
	return 2 + length, nil
}

// Type codes of the Capabilities which are used as Parameter(s)
const (
	_ = iota
	CAPABILITY_MULTI_PROTOCOl
	CAPABILITY_ROUTE_REFRESH
	CAPABILITY_ROUTE_FILTERING
	CAPABILITY_MULTIPLE_ROUTES
	CAPABILITY_EXTENDED_NEXTHOP

	CAPABILITY_GRACEFUL_RESTART = 64
	CAPABILITY_AS4              = 65
)

type CapabilityAS4 uint32

func (c *CapabilityAS4) Len() int { return 4 }
func (c *CapabilityAS4) Code() int { return CAPABILITY_AS4 }

func (c *CapabilityAS4) Bytes() []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(*c))
	return buf
}

func (c *CapabilityAS4) SetBytes(buf []byte) (int, error) {
	if len(buf) < 4 {
		return 0, errBuf
	}
	*c = CapabilityAS4(binary.BigEndian.Uint32(buf))
	return 5, nil
}
