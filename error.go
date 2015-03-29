package bgp

import "strconv"

// Error is an error the BGP protocol can return.
type Error struct {
	Code    int	// Code as defined in RFC 4271.
	Subcode int	// Subcode as defined in RFC 4271.
	Err     string  // Non mandatory extra text added by this package.
}

// NewError returns a pointer to an Error.
func NewError(code, subcode int, extra string) *Error {
	return &Error{code, subcode, extra}
}

func (e *Error) Error() string {
	s := "bgp: "
	if v, ok := errorCodes[e.Code]; ok {
		s += v
	} else {
		s += strconv.Itoa(e.Code)
	}
	s += ": "

	v := strconv.Itoa(e.Subcode)
	switch e.Code {
	case 1:
		if _, ok := errorSubcodesHeader[e.Subcode]; ok {
			v = errorSubcodesHeader[e.Subcode]
		}
	case 2:
		if _, ok := errorSubcodesOpen[e.Subcode]; ok {
			v = errorSubcodesOpen[e.Subcode]
		}
	case 3:
		if _, ok := errorSubcodesUpdate[e.Subcode]; ok {
			v = errorSubcodesUpdate[e.Subcode]
		}
	}
	s += v
	if e.Err != "" {
		s += ": " + e.Err
	}
	return s
}

var errorCodes = map[int]string{
	1: "Message Header Error",
	2: "OPEN Message Error",
	3: "UPDATE Message Error",
	4: "Hold Timer Expired",
	5: "Finite State Machine Error",
	6: "Cease",
}

var errorSubcodesHeader = map[int]string{
	1: "Connection Not Synchronized",
	2: "Bad Message Length",
	3: "Bad Message Type",
}

var errorSubcodesOpen = map[int]string{
	1: "Unsupported Version Number",
	2: "Bad Peer AS",
	3: "Bad BGP Identifier",
	4: "Unsupported Optional Parameter",
	// 5 deprecated
	6: "Unacceptable Hold Time",
}

var errorSubcodesUpdate = map[int]string{
	1: "Malformed Attribute List",
	2: "Unrecognized Well-known Attribute",
	3: "Missing Well-known Attribute",
	4: "Attribute Flags Error",
	5: "Attribute Length Error",
	6: "Invalid ORIGIN Attribute",
	// 7 deprecated
	8:  "Invalid NEXT_HOP Attribute",
	9:  "Optional Attribute Error",
	10: "Invalid Network Field",
	11: "Malformed AS_PATH",
}
