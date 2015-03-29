[![Build Status](https://travis-ci.org/miekg/bgp.svg?branch=master)](https://travis-ci.org/miekg/bgp)

# BGP

BGP is a BGP-4 implementation in Go.

## RFCs

* <http://www.rfc-editor.org/rfc/rfc4271.txt>

## Notes

client.Open - send open
client.Update - send Update
client.KeepAlive - etc.

## TODO

* fix all error uses
* make an actual client
* create server infra ala net/http, godns
