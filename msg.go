package bgp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// pack converts a header into wireformat and stores the result in buf
func (h *Header) pack(buf []byte) (int, error) {
	if len(buf) < headerLen {
		return 0, NewError(1, 2, fmt.Sprintf("pack: buffer size too small: %d < %d", len(buf), headerLen))
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
		return 0, NewError(1, 2, fmt.Sprintf("unpack: buffer size too small: %d < %d", len(buf), headerLen))
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
func (lp *Prefix) pack(buf []byte) (int, error) {
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
func (lp *Prefix) unpack(buf []byte) (int, error) {
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
	if mod := lp.Length % 8; mod != 0 {
		// wondering about dd
		buf[2+mod] &= ^(0xFF >> mod)
	}

	return 1 + int(lp.Length/8), nil
}

// pack convert to writeformat.
func (pa *PathAttr) pack(buf []byte) (int, error) {
	if len(buf) < 4 {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}
	buf[0] = pa.Flags
	buf[1] = pa.Code
	if pa.Flags&FlagLength == FlagLength {
		binary.BigEndian.PutUint16(buf[2:], uint16(len(pa.Value)))
	} else {
		buf[2] = uint8(len(pa.Value))
	}
	return 0, nil
}

// unpack converts to a PathAttr
func (pa *PathAttr) unpack(buf []byte) (int, error) {
	return 0, nil
}

// pack converts a Parameter to wireformat.
func (p *Parameter) pack(buf []byte) (int, error) {
	if len(buf) < 3 {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}
	buf[0] = p.Type
	buf[1] = uint8(len(p.Value))
	if len(buf[2:]) < len(p.Value) {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}
	for i := 0; i < len(p.Value); i++ {
		buf[i+2] = p.Value[i]
	}
	return 2 + len(p.Value), nil
}

// unpack converts the wireformat back to a Parameter.
func (p *Parameter) unpack(buf []byte) (int, error) {
	if len(buf) < 3 {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}
	p.Type = buf[0]
	length := int(buf[1])
	if len(buf[2:]) < length {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}
	p.Value = make([]byte, length)
	for i := 0; i < length; i++ {
		p.Value[i] = buf[i+2]
	}
	return 2 + length, nil
}

// Pack converts an OPEN message to wire format. Note that unlike Unpack, Pack also
// handles the header of the message.
func (m *OPEN) Pack(buf []byte) (int, error) {
	m.Length = uint16(m.Len())
	m.Type = typeOpen // be sure we're encoding an OPEN message

	offset := 0

	n, err := m.Header.pack(buf[offset:])
	if err != nil {
		return offset, err
	}
	offset += n
	buf[offset] = m.Version
	offset++

	binary.BigEndian.PutUint16(buf[offset:], m.MyAS)
	offset += 2

	binary.BigEndian.PutUint16(buf[offset:], m.HoldTime)
	offset += 2

	buf[offset], buf[offset+1], buf[offset+2], buf[offset+3] =
		m.BGPIdentifier[0], m.BGPIdentifier[1], m.BGPIdentifier[2], m.BGPIdentifier[3]
	offset += 4

	// Save for parameter length
	plengthOffset := offset
	offset++

	l := 0
	for _, p := range m.Parameters {
		n, err := p.pack(buf[offset:])
		if err != nil {
			return offset, err
		}
		l += p.len()
		offset += n
	}
	buf[plengthOffset] = uint8(l)
	return offset, nil
}

// Unpack converts wire format in buf to an OPEN message.
// The header should be already parsed and buf should start on the
// beginning of the message. The header should also already be set in m.
// Unpack returns the amount of bytes parsed or an error.
func (m *OPEN) Unpack(buf []byte) (int, error) {
	if len(buf) < int(m.Length)-headerLen {
		return 0, NewError(2, 0, fmt.Sprintf("buffer size too small: %d < %d", len(buf), m.Length-headerLen))
	}

	offset := 0

	m.Version = buf[offset]
	offset++

	m.MyAS = binary.BigEndian.Uint16(buf[offset:])
	offset += 2

	m.HoldTime = binary.BigEndian.Uint16(buf[offset:])
	offset += 2

	m.BGPIdentifier = net.IPv4(0, 0, 0, 0)
	m.BGPIdentifier[0], m.BGPIdentifier[1], m.BGPIdentifier[2], m.BGPIdentifier[3] =
		buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]
	offset += 4

	pLength := int(buf[offset])
	offset++
	if len(buf) < offset+pLength {
		return offset, NewError(2, 0, fmt.Sprintf("bgp: buffer size too small: %d < %d", len(buf), offset+pLength))
	}

	i := 0
	for i < pLength {
		p := Parameter{}
		n, e := p.unpack(buf[i+offset:])
		if e != nil {
			return offset, e
		}
		i += n
		offset += n
		m.Parameters = append(m.Parameters, p)
	}
	return offset, nil
}

// Pack converts an KEEPALIVE mesasge to wire format.
func (m *KEEPALIVE) Pack(buf []byte) (int, error) {
	if len(buf) < m.Len() {
		return 0, NewError(1, 2, "buffer size too small")
	}

	m.Length = uint16(m.Len())
	m.Type = typeKeepalive

	n, err := m.Header.pack(buf)
	if err != nil {
		return n, err
	}
	return n, nil
}

// Unpack converts wire format in buf to an KEEPALIVE message.
func (m *KEEPALIVE) Unpack(buf []byte) (int, error) {
	// a noop because a KEEPALIVE is *just* the header and it should
	// already parsed.
	return 0, nil // 1, nil?
}

// Unpack converts the wire format in buf to a BGP message. The first parsed
// message is returned together with the new offset in buf. If the parsing
// fails an error is returned.
func Unpack(buf []byte) (Message, int, error) {
	offset := 0

	h := new(Header)
	n, e := h.unpack(buf)
	offset += n
	if e != nil {
		return nil, offset, e
	}

	switch h.Type {
	case typeOpen:
		o := &OPEN{Header: h}
		n, e = o.Unpack(buf[offset:])
		offset += n
		if e != nil {
			return nil, offset, e
		}
		return o, offset, nil
	case typeUpdate:
		u := &UPDATE{Header: h}
		return u, offset, nil
		// TODO
	case typeKeepalive:
		k := &KEEPALIVE{Header: h}
		return k, offset, nil
	}
	return nil, n, NewError(1, 3, fmt.Sprintf("bad type: %d", h.Type))
}

// Packs convert Message into wireformat and stores the result in buf. It
// returns the new offset in buf or an error.
func Pack(buf []byte, m Message) (int, error) {
	switch x := m.(type) {
	case *OPEN:
		return x.Pack(buf)
	}
	return 0, NewError(1, 3, "")
}
