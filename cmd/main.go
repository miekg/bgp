package main

import (
	"log"
	"net"

	"github.com/miekg/bgp"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:179")
	if err != nil {
		log.Fatalf("%s", err)
	}

	req := &bgp.Open{Header: &bgp.Header{Type: bgp.OPEN}, Version: bgp.Version,
		MyAS: bgp.AS_TRANS, HoldTime: 80,
		BGPIdentifier: net.ParseIP("127.0.0.1").To4()}

	req.Par

	log.Printf("%+v\n", req)

	resp, err := bgp.Do(conn, req)
	if err != nil {
		log.Fatalf("%s", err)
	}

	log.Printf("%+v\n", resp)
}
