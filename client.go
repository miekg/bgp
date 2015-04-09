package bgp

import (
	"fmt"
	"net"
)

// Do sends a bgp message to the connection conn and waits for a reply.
// The reply message is returned or an error, if one is encountered.
func Do(conn net.Conn, m Msg) (Msg, error) {
	buf := bytes(m)
	n, err := conn.Write(buf)
	if err != nil {
		return nil, err
	}

	buf1 := make([]byte, MaxSize)
	n, err = conn.Read(buf1)
	if err != nil {
		return nil, err
	}
	buf1 = buf1[:n]

	fmt.Printf("%v\n", buf1)
	m1, n, err := setBytes(buf1)
	if err != nil {
		return nil, err
	}
	return m1, nil
}
