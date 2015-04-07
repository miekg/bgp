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

	req := &bgp.Open{Header: &bgp.Header{Type: bgp.OPEN},
		Version:       bgp.Version,
		MyAS:          bgp.AS_TRANS,
		HoldTime:      80,
		BGPIdentifier: net.ParseIP("127.0.0.1").To4()}

	// Say we can do 32 bit ASN
	req.Parameters = append(req.Parameters, bgp.Parameter{bgp.CAPABILITY, []bgp.TLV{bgp.CapabilityAS4{80000}}})

	log.Printf("%s\n", req)

	resp, err := bgp.Do(conn, req)
	if err != nil {
		log.Fatalf("%s", err)
	}

	log.Printf("%s\n", resp)
}
