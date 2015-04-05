package bgp

import "strconv"

// Error is an error the BGP protocol can return.
type Error struct {
	Code    int    // Code as defined in RFC 4271.
	Subcode int    // Subcode as defined in RFC 4271.
	Err     string // Non mandatory extra text added by this package.
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
	1: "message header error",
	2: "OPEN message error",
	3: "UPDATE message error",
	4: "hold timer expired",
	5: "finite state machine error",
	6: "cease",
}

var errorSubcodesHeader = map[int]string{
	1: "connection not synchronized",
	2: "bad message length",
	3: "bad message type",
}

var errorSubcodesOpen = map[int]string{
	1: "unsupported version number",
	2: "bad peer AS",
	3: "bad BGP identifier",
	4: "unsupported optional parameter",
	// 5 deprecated
	6: "unacceptable hold time",
	7: "unsupported capability",
}

var errorSubcodesUpdate = map[int]string{
	1: "malformed attribute list",
	2: "unrecognized well-known attribute",
	3: "missing well-known attribute",
	4: "attribute flags error",
	5: "attribute length error",
	6: "invalid ORIGIN attribute",
	// 7 deprecated
	8:  "invalid NEXT_HOP attribute",
	9:  "optional attribute error",
	10: "invalid network field",
	11: "malformed AS_PATH",
}
