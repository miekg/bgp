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

func (p Parameter) Len() int {
	l := 1
	for _, o := range p.Options {
		l += o.Len()
	}
	return l
}

func (p Parameter) Code() int { return int(p.Type) }

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

func (p Parameter) SetBytes(buf []byte) (int, error) {
	if len(buf) < 3 {
		return 0, errBuf
	}
	p.Type = buf[0]
	length := int(buf[1])
	if len(buf) < length {
		return 0, errBuf
	}
	switch p.Type {
	case CAPABILITY:
		i := 0
		Capabilities:
		for i < length {
			// look ahead a bit
			switch buf[i+2] {
			case CAPABILITY_AS4:
				c := CapabilityAS4{}
				n, e := c.SetBytes(buf[i:])
				if e != nil {
					return i + n, e
				}
				i += n
				p.Options = append(p.Options, c)
			default:
				break Capabilities
			}
		}

	default:
		println("bgp: unknown type", p.Type)
	}
	return length+2, nil	// Add 2 for the 2 byte header
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

// CapabilityAS4 announces we support 32 bit AS numbers.
type CapabilityAS4 struct {
	ASN uint32
}

func (c CapabilityAS4) Code() uint8 { return CAPABILITY_AS4 }
func (c CapabilityAS4) Len() int    { return 2 + 4 }

func (c CapabilityAS4) Bytes() []byte {
	buf := make([]byte, c.Len())
	buf[0] = c.Code()
	buf[1] = 4
	binary.BigEndian.PutUint32(buf, c.ASN)
	return buf
}

func (c CapabilityAS4) SetBytes(buf []byte) (int, error) {
	if len(buf) < 6 {
		return 0, errBuf
	}
	c.ASN = binary.BigEndian.Uint32(buf[2:])
	return 7, nil
}
