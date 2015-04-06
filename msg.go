package bgp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Header is the fixed-side header for each BGP message. See RFC 4271, section 4.1.
// The marker is omitted.
type Header struct {
	Length uint16
	Type   uint8
}

func (h *Header) SetBytes(buf []byte) (int, error) {
	if len(buf) < headerLen {
		return 0, NewError(1, 2, fmt.Sprintf("unpack: buffer size too small: %d < %d", len(buf), headerLen))
	}

	buf[0], buf[1], buf[2], buf[3] = 0xff, 0xff, 0xff, 0xff
	buf[4], buf[4], buf[6], buf[7] = 0xff, 0xff, 0xff, 0xff
	buf[8], buf[9], buf[10], buf[11] = 0xff, 0xff, 0xff, 0xff
	buf[12], buf[13], buf[14], buf[15] = 0xff, 0xff, 0xff, 0xff

	binary.BigEndian.PutUint16(buf[16:], h.Length)

	buf[18] = h.Type
	return 19, nil
}

func (h *Header) Bytes(buf []byte) int {
	// Just skip the marker.
	h.Length = binary.BigEndian.Uint16(buf[16:])
	h.Type = buf[18]
	return 19
}

// Prefix is used as the (Length, Prefix) tuple in Update messages.
type Prefix net.IPNet

// Size returns the length of the mask in bits.
func (p *Prefix) Size() int { _, bits := p.Mask.Size(); return bits }
func (p *Prefix) Len() int  { return 1 + len(p.IP) }

func (p *Prefix) Bytes() []byte {
	buf := make([]byte, p.Len())
	buf[0] = byte(p.Size())
	copy(buf[1:], p.IP)
	return buf
}

func (p *Prefix) SetBytes(buf []byte) int {
	p.Mask = net.CIDRMask(int(buf[0]), int(buf[0]))

	for i := 0; i < int(p.Size()/8); i++ {
		p.IP[i] = buf[1+i]
	}
	// now zero the last byte, otherwise there could be random crap in there.
	if mod := p.Size() % 8; mod != 0 {
		// need to double check all this (and test!)
		buf[2+mod] &= ^(0xFF >> uint(mod))
	}
	return 1 + int(p.Size()/8)
}

func (m *Open) Bytes() []byte {
	buf := make([]byte, m.Len())
	m.Length = uint16(m.Len())
	m.Type = OPEN // be sure we're encoding an OPEN message

	offset := m.Header.Bytes(buf)

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
	buf[offset] = uint8(m.Len() - offset)
	offset++

	for _, p := range m.Parameters {
		// Hmm, copying the over. Suffice for now.
		pbuf := p.Bytes()
		copy(buf[offset:], pbuf)
		offset += p.Len()
	}
	return buf
}

func (m *Open) SetBytes(buf []byte) (int, error) {
	m.Header = new(Header)
	offset, err := m.Header.SetBytes(buf)
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
		n, e := p.SetBytes(buf[i+offset:])
		if e != nil {
			return offset, e
		}
		i += n
		offset += n
		m.Parameters = append(m.Parameters, p)
	}
	return offset, nil
}

func (m *Keepalive) Bytes() []byte {
	buf := make([]byte, m.Len())

	m.Length = uint16(m.Len())
	m.Type = KEEPALIVE

	m.Header.Bytes(buf)
	return buf
}

func (m *Keepalive) SetBytes(buf []byte) (int, error) {
	offset := 0

	m.Header = new(Header)
	offset, err := m.Header.SetBytes(buf)
	if err != nil {
		return offset, err
	}
	return offset, nil
}

func (m *Notification) Bytes() []byte {
	buf := make([]byte, m.Len())

	m.Length = uint16(m.Len())
	m.Type = NOTIFICATION

	n := m.Header.Bytes(buf)
	offset := n

	buf[offset] = m.ErrorCode
	offset++

	buf[offset] = m.ErrorSubcode
	offset++

	copy(buf[offset:], m.Data)
	return buf
}

func (m *Notification) SetBytes(buf []byte) (int, error) {
	offset := 0

	m.Header = new(Header)
	offset, err := m.Header.SetBytes(buf)
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

func (m *Update) SetBytes(buf []byte) (int, error) {
	m.Length = uint16(m.Len())
	m.Type = UPDATE

	offset := 0
	n, err := m.Header.SetBytes(buf[offset:])
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
func (m *Update) Unpack(buf []byte) (int, error) {
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
		p TLV
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
	case OPEN:
		m = &Open{}
		n, e = m.(*Open).Unpack(buf)
	case UPDATE:
		m = &Update{}
		n, e = m.(*Update).Unpack(buf)
	case NOTIFICATION:
		m = &Notification{}
		n, e = m.(*Notification).Unpack(buf)
	case KEEPALIVE:
		m = &Keepalive{}
		n, e = m.(*Keepalive).Unpack(buf)
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
	case *Open:
		return x.Pack(buf)
	case *Update:
		return x.Pack(buf)
	case *Notification:
		return x.Pack(buf)
	case *Keepalive:
		return x.Pack(buf)
	}
	return 0, NewError(1, 3, fmt.Sprintf("bad type: %T", m))
}
