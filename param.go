package bgp

// The optional Parameters types that are defined.
const (
	CAPABILITY = 2
)

// Parameter is used in the Open message to negotiate options.
type Parameter struct {
	Type  uint8
	Options []TLV
}

func (p *Parameter) Len() int {
	l := 1
	for _, o := range p.Options {
		l += o.Len()
	}
	return l
}

func (p *Parameter) Bytes() []byte {
	buf := make([]byte, p.Len())
	buf[0] = p.Type
	buf[1] = uint8(len(p.Value))
	for i := 0; i < len(p.Value); i++ {
		buf[i+2] = p.Value[i]
	}
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
		p.Value[i] = buf[i+2]
	}
	return 2 + length, nil
}


// Type codes of the Capabilities which are used as Parameter
const (
	_ = iota
	CAPABILITY_MULTI_PROTOCOl
	CAPABILITY_ROUTE_REFRESH
	CAPABILITY_ROUTE_FILTERING
	CAPABILITY_MULTIPLE_ROUTES
	CAPABILITY_EXTENDED_NEXThOp

	CAPABILITY_GRACEFUL_RESTART = 64
	CAPABILITY_AS4        = 65
)

type CapabilityAS4 struct {
	// length, always 4
	ASN uint32
}
