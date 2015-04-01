[![Build Status](https://travis-ci.org/miekg/bgp.svg?branch=master)](https://travis-ci.org/miekg/bgp)

# BGP

BGP is a BGP-4 implementation in Go.

## RFCs

* BGP Communities: <https://tools.ietf.org/html/rfc1997>
* BGP Extended Communities: <https://tools.ietf.org/html/rfc4360>
* BGP-4: <https://tools.ietf.org/html/rfc4271>

## Notes

## TODO

* fix all error uses
* create server infra ala net/http, godns
* Not sure about Pack/Unpack names maybe Marshall/Unmarshall
* Fix Path Attributes, these are like dns RR's, define an interface
    and use reflection to pack/unpack.
