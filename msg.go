package bgp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// pack converts a header into wireformat and stores the result in buf.
func (h *Header) pack(buf []byte) (int, error) {
	if len(buf) < headerLen {
		return 0, NewError(1, 2, fmt.Sprintf("pack: buffer size too small: %d < %d", len(buf), headerLen))
	}
	// Marker.
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
	// Just skip the marker.
	h.Length = binary.BigEndian.Uint16(buf[16:])
	h.Type = buf[18]
	return 19, nil
}

// pack converts Prefix into wireformat.
func (p *Prefix) pack(buf []byte) (int, error) {
	if len(buf) < 1 {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}
	buf[0] = byte(p.Size())

	if len(buf[1:]) < int(p.Size()/8) {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}

	for i := 0; i < int(p.Size()/8); i++ {
		buf[1+i] = p.IP[i]
	}
	return 1 + int(p.Size()/8), nil
}

// unpack converts the wireformat to a Prefix.
func (p *Prefix) unpack(buf []byte) (int, error) {
	if len(buf) < 1 {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}

	p.Mask = net.CIDRMask(int(buf[0]), int(buf[0]))

	if len(buf[1:]) < int(p.Size()/8) {
		return 0, fmt.Errorf("bgp: buffer size too small")
	}

	for i := 0; i < int(p.Size()/8); i++ {
		p.IP[i] = buf[1+i]
	}
	// now zero the last byte, otherwise there could be random crap in there.
	if mod := p.Size() % 8; mod != 0 {
		// need to double check all this (and test!)
		buf[2+mod] &= ^(0xFF >> uint(mod))
	}

	return 1 + int(p.Size()/8), nil
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

// Pack converts an OPEN message to wire format.
func (m *OPEN) Pack(buf []byte) (int, error) {
	m.Length = uint16(m.Len())
	m.Type = Open // be sure we're encoding an OPEN message

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
	buf[plengthOffset] = byte(l)
	return offset, nil
}

// Unpack converts wire format in buf to an OPEN message.
// Unpack returns the amount of bytes parsed or an error.
func (m *OPEN) Unpack(buf []byte) (int, error) {
	offset := 0

	m.Header = new(Header)
	offset, err := m.Header.unpack(buf)
	if err != nil {
		return offset, err
	}

	if len(buf) < int(m.Length) {
		return 0, NewError(2, 0, fmt.Sprintf("buffer size too small: %d < %d", len(buf), m.Length))
	}

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
		return offset, NewError(2, 0, fmt.Sprintf("buffer size too small: %d < %d", len(buf), offset+pLength))
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
	m.Type = Keepalive

	n, err := m.Header.pack(buf)
	if err != nil {
		return n, err
	}
	return n, nil
}

// Unpack converts wire format in buf to an KEEPALIVE message.
func (m *KEEPALIVE) Unpack(buf []byte) (int, error) {
	offset := 0

	m.Header = new(Header)
	offset, err := m.Header.unpack(buf)
	if err != nil {
		return offset, err
	}
	return offset, nil
}

// Pack converts an NOTIFICATION mesasge to wire format. Unlike Unpack, pack also
// handles the header of the message.
func (m *NOTIFICATION) Pack(buf []byte) (int, error) {
	if len(buf) < m.Len() {
		return 0, NewError(1, 2, "buffer size too small")
	}

	offset := 0

	m.Length = uint16(m.Len())
	m.Type = Notification

	n, err := m.Header.pack(buf[offset:])
	if err != nil {
		return offset, err
	}
	offset += n

	buf[offset] = m.ErrorCode
	offset++

	buf[offset] = m.ErrorSubcode
	offset++

	for i := 0; i < len(m.Data); i++ {
		buf[offset+i] = m.Data[i]
	}
	offset += len(m.Data)

	return offset, nil
}

// Unpack converts wire format in buf to an NOTIFICATION message.
// Unpack returns the amount of bytes parsed or an error.
func (m *NOTIFICATION) Unpack(buf []byte) (int, error) {
	offset := 0

	m.Header = new(Header)
	offset, err := m.Header.unpack(buf)
	if err != nil {
		return offset, err
	}

	if len(buf) < int(m.Length) {
		return 0, NewError(0, 0, fmt.Sprintf("buffer size too small: %d < %d", len(buf), m.Length))
	}

	offset = 0
	m.ErrorCode = buf[offset]
	offset++

	m.ErrorSubcode = buf[offset]
	offset++

	// TODO(miek): copy data until end of message

	return offset, nil
}

// Pack converts an UPDATE message to wire format.
// Unpack returns the amount of bytes parsed or an error.
func (m *UPDATE) Pack(buf []byte) (int, error) {
	m.Length = uint16(m.Len())
	m.Type = Update

	offset := 0
	n, err := m.Header.pack(buf[offset:])
	if err != nil {
		return offset, err
	}
	offset += n

	// withdrawnRoutesLength
	wlengthOffset := offset
	offset += 2

	l := 0
	for _, w := range m.WithdrawnRoutes {
		n, err := w.pack(buf[offset:])
		if err != nil {
			return offset, err
		}
		l += w.len()
		offset += n
	}
	binary.BigEndian.PutUint16(buf[wlengthOffset:], uint16(l))

	plengthOffset := offset
	for _, p := range m.PathAttrs {
		n, err := p.Pack(buf[offset:])
		if err != nil {
			return offset, err
		}
		l += p.Len()
		offset += n
	}
	binary.BigEndian.PutUint16(buf[plengthOffset:], uint16(l))

	for _, r := range m.ReachabilityInfo {
		n, err := r.pack(buf[offset:])
		if err != nil {
			return offset, err
		}
		l += r.len()
		offset += n
	}

	return offset, nil
}

// Unpack converts wire format in buf to an UPDATE message.
// Unpack returns the amount of bytes parsed or an error.
func (m *UPDATE) Unpack(buf []byte) (int, error) {
	offset := 0

	m.Header = new(Header)
	offset, err := m.Header.unpack(buf)
	if err != nil {
		return offset, err
	}

	if len(buf) < int(m.Length) {
		return 0, NewError(3, 0, fmt.Sprintf("buffer size too small: %d < %d", len(buf), m.Length))
	}

	offset = 0

	wLength := int(binary.BigEndian.Uint16(buf[offset:]))
	offset += 2
	if len(buf) < offset+wLength {
		return offset, NewError(3, 0, fmt.Sprintf("buffer size too small: %d < %d", len(buf), offset+wLength))
	}

	i := 0
	for i < wLength {
		p := Prefix{}
		n, e := p.unpack(buf[i+offset:])
		if e != nil {
			return offset, e
		}
		i += n
		offset += n
		m.WithdrawnRoutes = append(m.WithdrawnRoutes, p)
	}

	pLength := int(binary.BigEndian.Uint16(buf[offset:]))
	offset += 2
	if len(buf) < offset+pLength {
		return offset, NewError(3, 0, fmt.Sprintf("buffer size too small: %d < %d", len(buf), offset+pLength))
	}

	i = 0
	var (
		p PathAttr
		e error
		n int
	)
	for i < pLength {
		switch buf[i+offset+1] { //second byte has the type TODO(miek): should check if the access is valid
		case ORIGIN:
			p = new(Origin)
			n, e = p.Unpack(buf[i+offset:])
			if e != nil {
				return offset, e
			}
		case AS_PATH:
			p = new(AsPath)
			n, e = p.Unpack(buf[i+offset:])
			if e != nil {
				return offset, e
			}
		case COMMUNITIES:
			p = new(Community)
			n, e = p.Unpack(buf[i+offset:])
			if e != nil {
				return offset, e
			}
		default:
			// unknown
		}
		i += n
		offset += n
		m.PathAttrs = append(m.PathAttrs, p)
	}

	rLength := int(m.Length) - offset
	if len(buf) < offset+rLength {
		return offset, NewError(3, 0, fmt.Sprintf("buffer size too small: %d < %d", len(buf), offset+rLength))
	}

	i = 0
	for i < rLength {
		r := Prefix{}
		n, e := r.unpack(buf[i+offset:])
		if e != nil {
			return offset, e
		}
		i += n
		offset += n
		m.ReachabilityInfo = append(m.ReachabilityInfo, r)
	}
	return offset, nil
}

// Unpack converts the wire format in buf to a BGP message. The first parsed
// message is returned together with the new offset in buf. If the parsing
// fails an error is returned.
func Unpack(buf []byte) (m Message, n int, e error) {
	if len(buf) < headerLen {
		return nil, 0, NewError(1, 2, fmt.Sprintf("pack: buffer size too small: %d < %d", len(buf), headerLen))
	}
	// Byte 18 has the type.
	switch buf[18] {
	case Open:
		m = &OPEN{}
		n, e = m.(*OPEN).Unpack(buf)
	case Update:
		m = &UPDATE{}
		n, e = m.(*UPDATE).Unpack(buf)
	case Notification:
		m = &NOTIFICATION{}
		n, e = m.(*NOTIFICATION).Unpack(buf)
	case Keepalive:
		m = &KEEPALIVE{}
		n, e = m.(*KEEPALIVE).Unpack(buf)
	default:
		return nil, 0, NewError(1, 3, fmt.Sprintf("bad type: %d", buf[18]))
	}
	if e != nil {
		return nil, n, e
	}
	return m, n, nil
}

// Packs convert Message into wireformat and stores the result in buf. It
// returns the new offset in buf or an error.
func Pack(buf []byte, m Message) (int, error) {
	switch x := m.(type) {
	case *OPEN:
		return x.Pack(buf)
	case *UPDATE:
		return x.Pack(buf)
	case *NOTIFICATION:
		return x.Pack(buf)
	case *KEEPALIVE:
		return x.Pack(buf)
	}
	return 0, NewError(1, 3, fmt.Sprintf("bad type: %T", m))
}
