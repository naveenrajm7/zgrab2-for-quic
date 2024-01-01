# H3 zgrab2 module

This module is used for HTTP/3 banner grabbing. 
It performs a normal HTTP scan and looks for the `alt-svc` header to search for potential H3 addresses. 
If an H3 address is found, it establishes an HTTP/3 connection using QUIC. 
The scan result includes the HTTP scan result, HTTP/3 scan result, and qlog data of the QUIC connection.


Please note that this module requires a compatible version of quic-go that supports HTTP/3 with QUIC.

Extras:
* Uses MultiResolver to support multiple IPs resolved by one domain.
