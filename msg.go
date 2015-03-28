package bgp

import (
	"encoding/binary"
	"fmt"
)

// pack converts a header into wireformat and stores the result in buf
func (h *Header) pack(buf []byte) (int, error) {
	if len(buf) < headerLen {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}
	buf[0], buf[1], buf[2], buf[3] = 0xff, 0xff, 0xff, 0xff
	buf[4], buf[4], buf[6], buf[7] = 0xff, 0xff, 0xff, 0xff
	buf[8], buf[9], buf[10], buf[11] = 0xff, 0xff, 0xff, 0xff
	buf[12], buf[13], buf[14], buf[15] = 0xff, 0xff, 0xff, 0xff

	binary.BigEndian.PutUint16(buf[16:], h.Length)

	buf[18] = h.Type
	return 19, nil
}

// unpack converts the wireformat to a header
func (h *Header) unpack(buf []byte) (int, error) {
	if len(buf) < headerLen {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}
	h.Marker[0], h.Marker[1], h.Marker[2], h.Marker[3] = buf[0], buf[1], buf[2], buf[3]
	h.Marker[4], h.Marker[5], h.Marker[6], h.Marker[7] = buf[4], buf[5], buf[6], buf[7]
	h.Marker[8], h.Marker[9], h.Marker[10], h.Marker[11] = buf[8], buf[9], buf[10], buf[11]
	h.Marker[12], h.Marker[13], h.Marker[14], h.Marker[15] = buf[12], buf[13], buf[14], buf[15]

	h.Length = binary.BigEndian.Uint16(buf[16:])

	h.Type = buf[18]
	return 19, nil
}

// pack convert LengthPrefix into wireformat.
func (lp *LengthPrefix) pack(buf []byte) (int, error) {
	if len(buf) < 1 {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}
	buf[0] = byte(lp.Length)

	if len(buf[1:]) < int(lp.Length/8) {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}

	for i := 0; i < int(lp.Length/8); i++ {
		buf[1+i] = lp.Prefix[i]
	}
	return 1 + int(lp.Length/8), nil
}

// unpack convert the wireformat to a LengthPrefix.
func (lp *LengthPrefix) unpack(buf []byte) (int, error) {
	if len(buf) < 1 {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}

	lp.Length = buf[0]

	if len(buf[1:]) < int(lp.Length/8) {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}

	for i := 0; i < int(lp.Length/8); i++ {
		lp.Prefix[i] = buf[1+i]
	}
	// now zero the last byte, otherwise there could be random crap in there.
	return 1 + int(lp.Length/8), nil
}

// pack convert to writeformat.
func (pa *PathAttribute) pack(buf []byte) (int, error) {
	if len(buf) < 4 {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}
	buf[0] = pa.Flags
	buf[1] = pa.Code
	// Check flags to see how many octects length has
	return 0, nil
}

// unpack converts to a PathAttribute
func (pa *PathAttribute) unpack(buf []byte) (int, error) {
	return 0, nil
}

// convert to wireformat.
func (p *Parameter) pack(buf []byte) (int, error) {
	if len(buf) < 3 {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}
	buf[0] = p.Type
	buf[1] = p.Length
	if len(buf[2:]) < int(p.Length) {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}
	for i := 0; i < int(p.Length); i++ {
		buf[i+2] = p.Value[i]
	}
	return 2 + int(p.Length), nil
}

// Convert back to Parameter
func (p *Parameter) unpack(buf []byte) (int, error) {
	if len(buf) < 3 {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}
	p.Type = buf[0]
	p.Length = buf[1]
	if len(buf[2:]) < int(p.Length) {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}
	for i := 0; i < int(p.Length); i++ {
		p.Value[i] = buf[i+2]
	}
	return 2 + int(p.Length), nil
}

// Pack converts an OPEN message to wire format.
func (m *OPEN) Pack(buf []byte) (int, error) {
	offset := 0

	// get length for tne

	n, err := m.Header.pack(buf[offset:])
	if err != nil {
		return offset, err
	}
	offset += n
	buf[offset] = m.Version
	offset++

	binary.BigEndian.PutUint16(buf[offset:], m.MyAutonomousSystem)
	offset += 2

	binary.BigEndian.PutUint16(buf[offset:], m.HoldTime)
	offset += 2

	buf[offset], buf[offset+1], buf[offset+2], buf[offset+3] =
		m.BGPIdentifier[0], m.BGPIdentifier[1], m.BGPIdentifier[2], m.BGPIdentifier[3]
	offset += 4

	// parameterslength
	l := 0
	for _, p := range *m.Parameters {
		l += p.len()
	}
	// if l > 255 -> problem, TODO
	buf[offset] = byte(l)
	offset++

	for _, p := range *m.Parameters {
		n, err := p.pack(buf[offset:])
		if err != nil {
			return offset, err
		}
		offset += n
	}
	return offset, nil
}

func (m *OPEN) Unpack(buf []byte) (int, error) {
	return 0, nil
}
