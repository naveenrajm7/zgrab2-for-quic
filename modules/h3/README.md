# H3 zgrab2 module

This module is used for HTTP/3 banner grabbing. 
It performs a normal HTTP scan and looks for the `alt-svc` header to search for potential H3 addresses. 
If an H3 address is found, it establishes an HTTP/3 connection using QUIC. 
The scan result includes the HTTP scan result, HTTP/3 scan result, and qlog data of the QUIC connection.


Please note that this module requires a compatible version of quic-go that supports HTTP/3 with QUIC.

Extras:
* Uses MultiResolver to support multiple IPs resolved by one domain.

## Other Tests

1. Version (2) Test
    To start version negotiation, pass invalid version number or reserved version number in the QUIC packet
    In this module, we send 0x3 as invalid version, the same is added in place of 0x1 in quic-go 
    So that the quic-go client itself will not reject saying the version is invalid.

2. Grease QUIC bit Test
    We advertise grease_quic_bit transport parameter by enabling greaseQuicBit in quic config
    We log the long header packet, if it has QUIC bit set 0. We conclude that it supports Grease QUIC bit.

