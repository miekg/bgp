package main

import (
	"log"
	"net"

	"github.com/miekg/bgp"
)

// Connect to a BGP server and send an Open message with a parameters
// advertizing that we can do 32 bit ASN.

func main() {
	conn, err := net.Dial("tcp", "localhost:179")
	if err != nil {
		log.Fatalf("%s", err)
	}

	// Create Open message...
	open := &bgp.Open{HoldTime: 80, BGPIdentifier: net.ParseIP("127.0.0.1").To4()}
	// ... with some capabilities.
	open.Parameters = make([]bgp.Parameter, 1)

	c := &bgp.Capability{}
	c.Append(bgp.CAP_AS4, 80000)

	open.Parameters[0].Append(bgp.CAP, c)

	log.Printf("%+v\n", open)

	resp, err := bgp.Do(conn, open)
	if err != nil {
		log.Fatalf("%s", err)
	}

	log.Printf("%+v\n", resp)
}
