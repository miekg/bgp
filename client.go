package bgp

import (
	"fmt"
	"net"
)

// Do sends a bgp message to the connection conn and waits for a reply.
// The reply message is returned or an error, if one is encountered.
func Do(conn net.Conn, m Message) (Message, error) {
	buf := Bytes(m)
	n, err := conn.Write(buf)
	fmt.Printf("%+v\n", buf)
	if err != nil {
		return nil, err
	}

	buf1 := make([]byte, MaxSize)
	n, err = conn.Read(buf1)
	if err != nil {
		return nil, err
	}
	buf1 = buf1[:n]
	fmt.Printf("%+v\n", buf1)

	m1, n, err := SetBytes(buf1)
	if err != nil {
		return nil, err
	}
	return m1, nil
}
