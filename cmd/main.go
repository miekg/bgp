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

	req := bgp.NewOPEN(10, 80, net.ParseIP("127.0.0.1"), nil)

	log.Printf("%+v\n", req)

	resp, err := bgp.Do(conn, req)
	if err != nil {
		log.Fatalf("%s", err)
	}

	log.Printf("%+v\n", resp)
}
