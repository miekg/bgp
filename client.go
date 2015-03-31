package bgp

import "net"

// Do sends a bgp message to the connection conn and waits for a reply.
// The reply message is returned or an error if one is encountered.
func Do(conn net.Conn, m Message) (Message, error) {
	buf := make([]byte, m.Len(), MaxSize)

	_, err := Pack(buf, m)
	if err != nil {
		return nil, err
	}

	n, err := conn.Write(buf)
	if err != nil {
		return nil, err
	}

	buf = buf[:MaxSize]
	n, err = conn.Read(buf)
	if err != nil {
		return nil, err
	}
	buf = buf[:n]

	m1, n, err := Unpack(buf)
	if err != nil {
		return nil, err
	}
	return m1, nil
}
