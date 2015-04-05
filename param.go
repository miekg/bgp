package bgp

// The optional Parameters types that are defines
const (
	CAPABILITY = 2
)

// The different Options that can be used in Parameters.
type Options interface {
	// Same as attr.go
}

// Parameter is used in the Open message to negotiate options.
type Parameter struct {
	Type  uint8
	Value []byte
}

func (p *Parameter) len() int { return 2 + len(p.Value) }

// Type codes of the Capabilities which are used as Parameter
const (
	_ = iota
	CAPABILITY_MULTI_PROTOCOl
	CAPABILITY_ROUTE_REFRESH
	CAPABILITY_ROUTE_FILTERING
	CAPABILITY_MULTIPLE_ROUTES
	CAPABILITY_EXTENDED_NEXThOp

	CAPABILITY_GRACEFUL_RESTART = 64
	CAPABILITY_32BIT_ASN        = 65
)

type Capability32bitASN struct {
	Type uint8 // Don't need type here, it's always the same
	// length
	ASN uint32
}
