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

	req := &OPEN{Header: &bgp.Header{Type: typeOpen}, Version: bgp.Version, MyAS: 10,
		HoldTime: 80, BGPIdentifier: net.ParseIP("127.0.0.1").To4(), Parameters: nil}

	log.Printf("%+v\n", req)

	resp, err := bgp.Do(conn, req)
	if err != nil {
		log.Fatalf("%s", err)
	}

	log.Printf("%+v\n", resp)
}
