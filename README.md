[![Build Status](https://travis-ci.org/miekg/bgp.svg?branch=master)](https://travis-ci.org/miekg/bgp)

# BGP

BGP is a BGP-4 implementation in Go.

## RFCs

* BGP Communities: <https://tools.ietf.org/html/rfc1997>
* Capabilities Advertisement with BGP-4: <https://tools.ietf.org/html/rfc3392>
* BGP-4: <https://tools.ietf.org/html/rfc4271>
* BGP Extended Communities: <https://tools.ietf.org/html/rfc4360>
* BGP 32 bit AS numbers: <https://tools.ietf.org/html/rfc4893>
* BGP 32 bit AS numbers: <https://tools.ietf.org/html/rfc6793>


## Notes


## TODO

* fix all error uses
* create server infra ala net/http, godns
* Fix Path Attributes, these are like dns RR's, define an interface
    and use reflection to pack/unpack.
* Unpack doesn't do header, Pack does do header
    Makes more sense if they *all* do or neither.
* Tests!
