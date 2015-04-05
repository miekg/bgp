package bgp

// The optional Parameters types that are defined.
const (
	CAPABILITY = 2
)

// Parameter is used in the Open message to negotiate options.
type Parameter struct {
	Type  uint8
	Options []Option
}

// The different Options that can be used in Parameters.
type Option interface {
	Len() int                   // Len returns the length of the option in bytes when in wire format.
	Pack([]byte) (int, error)   // Pack converts the option to wire format.
	Unpack([]byte) (int, error) // Unpack converts the option from wire format.
}

//func (p *Parameter) len() int { return 2 + len(p.Value) }

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
