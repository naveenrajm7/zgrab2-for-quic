package zgrab2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Fake DNS Resolver, to force a DNS lookup to return a pinned address
// Inspired by the golang net/dnsclient_unix_test.go code
//
// For a given IP, create a new Resolver that wraps a fake
// DNS server. This resolver will always return an IP that
// is represented by "ipstr", for DNS queries of the same
// IP type.  Otherwise, it will return a DNS lookup error.
func NewFakeResolver(ipstr string) (*net.Resolver, error) {
	ip := net.ParseIP(ipstr)
	if len(ip) < 4 {
		return nil, fmt.Errorf("Fake resolver can't use non-IP '%s'", ipstr)
	}
	fDNS := FakeDNSServer{
		IPs: []net.IP{ip},
	}
	return &net.Resolver{
		PreferGo: true, // Needed to force the use of the Go internal resolver
		Dial:     fDNS.DialContext,
	}, nil
}

// NewMultiFakeResolver creates a new Resolver that wraps a fake DNS server.
// This resolver will always return a list of IPs that are represented by "ips",
// for DNS queries of the same IP type. Otherwise, it will return a DNS lookup error.
// This function is useful when you want to simulate DNS responses with multiple IPs.
//
// Parameters:
// - ips: A slice of net.IP that the resolver should return for DNS queries.
//
// Returns:
// - A pointer to the new net.Resolver that uses the fake DNS server.
// - An error if any of the provided IPs is not a valid IPv4 or IPv6 address.
func NewMultiFakeResolver(ips []net.IP) (*net.Resolver, error) {
	for _, i := range ips {
		if s := len(i); s != 4 && s != 16 {
			return nil, fmt.Errorf("Fake resolver can't use non-IP '%s'", i.String())
		}
	}
	fDNS := FakeDNSServer{
		IPs: ips,
	}
	return &net.Resolver{
		PreferGo: true, // Needed to force the use of the Go internal resolver
		Dial:     fDNS.DialContext,
	}, nil
}

type FakeDNSServer struct {
	// Any domain name will resolve to these IPs. It can be a mix of ipv4 and ipv6
	IPs []net.IP
}

// For a given DNS query, return the hard-coded IP that is part of
// FakeDNSServer.
//
// It will work with either ipv4 or ipv6 addresses; if a TypeA question
// is received, we will only return the IP if what we have to return is
// ipv4.  The same for TypeAAAA and ipv6.
func (f *FakeDNSServer) fakeDNS(s string, dmsg dnsmessage.Message) (r dnsmessage.Message, err error) {

	r = dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       dmsg.ID,
			Response: true,
		},
		Questions: dmsg.Questions,
	}
	for _, ip := range f.IPs {
		ipv4 := ip.To4()
		switch t := dmsg.Questions[0].Type; {
		case t == dnsmessage.TypeA && ipv4 != nil:
			body := dnsmessage.AResource{}
			copy(body.A[:], ipv4)
			r.Answers = append(r.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:   dmsg.Questions[0].Name,
					Type:   dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Length: 4,
				},
				Body: &body,
			})
		case t == dnsmessage.TypeAAAA && ipv4 == nil:
			body := dnsmessage.AAAAResource{}
			copy(body.AAAA[:], ip.To16())
			r.Answers = append(r.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:   dmsg.Questions[0].Name,
					Type:   dnsmessage.TypeAAAA,
					Class:  dnsmessage.ClassINET,
					Length: 16,
				},
				Body: &body,
			})
		}
	}
	if len(r.Answers) == 0 {
		r.Header.RCode = dnsmessage.RCodeNameError
	}
	return r, nil
}

// This merely wraps a custom net.Conn, that is only good for DNS
// messages
func (f *FakeDNSServer) DialContext(ctx context.Context, network,
	address string) (net.Conn, error) {

	conn := &fakeDNSPacketConn{
		fakeDNSConn: fakeDNSConn{
			server:  f,
			network: network,
			address: address,
		},
	}
	return conn, nil
}

type fakeDNSConn struct {
	net.Conn
	server  *FakeDNSServer
	network string
	address string
	dmsg    dnsmessage.Message
}

func (fc *fakeDNSConn) Read(b []byte) (int, error) {
	resp, err := fc.server.fakeDNS(fc.address, fc.dmsg)
	if err != nil {
		return 0, err
	}

	bb := make([]byte, 2, 514)
	bb, err = resp.AppendPack(bb)
	if err != nil {
		return 0, fmt.Errorf("cannot marshal DNS message: %v", err)
	}

	bb = bb[2:]
	if len(b) < len(bb) {
		return 0, errors.New("read would fragment DNS message")
	}

	copy(b, bb)
	return len(bb), nil
}

func (fc *fakeDNSConn) Write(b []byte) (int, error) {
	if fc.dmsg.Unpack(b) != nil {
		return 0, fmt.Errorf("cannot unmarshal DNS message fake %s (%d)", fc.network, len(b))
	}
	return len(b), nil
}

func (fc *fakeDNSConn) SetDeadline(deadline time.Time) error {
	return nil
}

func (fc *fakeDNSConn) Close() error {
	return nil
}

type fakeDNSPacketConn struct {
	net.PacketConn
	fakeDNSConn
}

func (f *fakeDNSPacketConn) SetDeadline(deadline time.Time) error {
	return nil
}

func (f *fakeDNSPacketConn) Close() error {
	return f.fakeDNSConn.Close()
}
