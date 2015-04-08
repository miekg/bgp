package bgp

import (
	"encoding/binary"
	"fmt"
	"net"
)

type header struct {
	Length uint16
	Type   uint8
}

func (h *header) bytes() []byte {
	buf := make([]byte, 19)
	buf[0], buf[1], buf[2], buf[3] = 0xff, 0xff, 0xff, 0xff
	buf[4], buf[5], buf[6], buf[7] = 0xff, 0xff, 0xff, 0xff
	buf[8], buf[9], buf[10], buf[11] = 0xff, 0xff, 0xff, 0xff
	buf[12], buf[13], buf[14], buf[15] = 0xff, 0xff, 0xff, 0xff

	binary.BigEndian.PutUint16(buf[16:], h.Length)
	buf[18] = h.Type

	return buf
}

func (h *header) setBytes(buf []byte) (int, error) {
	if len(buf) < headerLen {
		return 0, NewError(1, 2, fmt.Sprintf("unpack: buffer size too small: %d < %d", len(buf), headerLen))
	}
	// Just skip the marker.
	h.Length = binary.BigEndian.Uint16(buf[16:])
	h.Type = buf[18]
	return 19, nil
}

// Prefix is used as the (Length, Prefix) tuple in Update messages.
type Prefix net.IPNet

func (p *Prefix) size() int { _, bits := p.Mask.Size(); return bits }
func (p *Prefix) bytes() []byte { return append([]byte{byte(p.size())}, p.IP...) }

func (p *Prefix) setBytes(buf []byte) (int, error) {
	p.Mask = net.CIDRMask(int(buf[0]), int(buf[0]))

	for i := 0; i < int(p.size()/8); i++ {
		p.IP[i] = buf[1+i]
	}
	// now zero the last byte, otherwise there could be random crap in there.
	if mod := p.size() % 8; mod != 0 {
		// need to double check all this (and test!)
		buf[2+mod] &= ^(0xFF >> uint(mod))
	}
	return 1 + int(p.size()/8), nil
}

func (m *Open) bytes() []byte {
	buf := make([]byte, 10)

	buf[0] = m.Version
	if m.Version == 0 {
		buf[0] = Version
	}
	binary.BigEndian.PutUint16(buf[1:], m.AS)
	if m.AS == 0 {
		binary.BigEndian.PutUint16(buf[1:], AS_TRANS)
	}
	binary.BigEndian.PutUint16(buf[3:], m.HoldTime)
	buf[5], buf[6], buf[7], buf[8] =
		m.BGPIdentifier[0], m.BGPIdentifier[1], m.BGPIdentifier[2], m.BGPIdentifier[3]

	pbuf := make([]byte, 0)
	for _, p := range m.Parameters {
		pbuf = append(pbuf, p.Bytes()...)
	}
	buf[9] = uint8(len(pbuf)) // Length of the parameters.
	buf = append(buf, pbuf...)

	m.header = &header{}
	m.Length = headerLen + uint16(10+len(pbuf))
	m.Type = open

	header := m.header.bytes()
	return append(header, buf...)
}

func (m *Open) setBytes(buf []byte) (int, error) {
	m.header = &header{}
	offset, err := m.header.setBytes(buf)
	if err != nil {
		return offset, err
	}

	if len(buf) < int(m.Length) {
		return 0, NewError(2, 0, fmt.Sprintf("buffer size too small: %d < %d", len(buf), m.Length))
	}

	buf = buf[offset:]
	m.Version = buf[0]
	m.AS = binary.BigEndian.Uint16(buf[1:])
	m.HoldTime = binary.BigEndian.Uint16(buf[3:])
	m.BGPIdentifier = net.IPv4(0, 0, 0, 0)
	m.BGPIdentifier[0], m.BGPIdentifier[1], m.BGPIdentifier[2], m.BGPIdentifier[3] =
		buf[5], buf[6], buf[7], buf[8]

	pLength := int(buf[9])
	// offset = 10
	if len(buf) < 10+pLength {
		return offset, NewError(2, 0, fmt.Sprintf("buffer size too small: %d < %d", len(buf), offset+pLength))
	}

	i := 0
	for i < pLength {
		p := Parameter{}
		n, e := p.SetBytes(buf[10+i:])
		if e != nil {
			return 10 + i, e
		}
		i += n
		m.Parameters = append(m.Parameters, p)
	}
	return offset + 10 + i, nil
}

func (m *Keepalive) bytes() []byte {
	m.Length = headerLen
	m.Type = keepalive

	header := m.header.bytes()
	return header
}

func (m *Keepalive) setBytes(buf []byte) (int, error) {
	offset := 0

	m.header = &header{}
	offset, err := m.header.setBytes(buf)
	if err != nil {
		return offset, err
	}
	return offset, nil
}

/*
func (m *Notification) bytes() []byte {
	m.Length = uint16(m.Len())
	m.Type = NOTIFICATION
	header := m.header.Bytes()

	buf := make([]byte, m.Len()-len(header))

	offset := 0

	buf[offset] = m.ErrorCode
	offset++

	buf[offset] = m.ErrorSubcode
	offset++

	copy(buf[offset:], m.Data)
	return append(header, buf...)
}

func (m *Notification) setBytes(buf []byte) (int, error) {
	m.header = &header
	offset, err := m.header.SetBytes(buf)
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

func (m *Update) setBytes(buf []byte) (int, error) {
	m.Length = uint16(m.Len())
	m.Type = UPDATE

	offset := 0
	n, err := m.header.SetBytes(buf[offset:])
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

	m.header = &header{}
	offset, err := m.header.unpack(buf)
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
*/

// setBytes converts the wire format in buf to a BGP message. The first parsed
// message is returned together with the new offset in buf. If the parsing
// fails an error is returned.
func setBytes(buf []byte) (m Message, n int, e error) {
	if len(buf) < headerLen {
		return nil, 0, NewError(1, 2, fmt.Sprintf("pack: buffer size too small: %d < %d", len(buf), headerLen))
	}
	// Byte 18 has the type.
	switch buf[18] {
	case open:
		m = &Open{}
		n, e = m.(*Open).setBytes(buf)
		//	case update:
		//		m = &Update{}
		//		n, e = m.(*Update).SetBytes(buf)
	case notification:
		m = &Notification{}
		n, e = m.(*Notification).setBytes(buf)
	case keepalive:
		m = &Keepalive{}
		n, e = m.(*Keepalive).setBytes(buf)
	default:
		return nil, 0, NewError(1, 3, fmt.Sprintf("bad type: %d", buf[18]))
	}
	if e != nil {
		return nil, n, e
	}
	return m, n, nil
}

// Bytes convert Message into wireformat and returns it as a byte slice.
func bytes(m Message) []byte {
	switch x := m.(type) {
	case *Open:
		return x.bytes()
		//	case *Update:
		//		return x.bytes()
	case *Notification:
		return x.bytes()
	case *Keepalive:
		return x.bytes()
	}
	return nil
}
