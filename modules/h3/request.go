package h3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/h3/blocklist"
)

var ErrTooManyH3Redirects = errors.New("too many h3 redirects")
var ErrRedirectWithCreds = errors.New("h3 redirect contains credentials")

type KV struct {
	Name   string
	Value  interface{}
	Conn   []byte            `json:"Conn,omitempty"`
	Stream *logging.StreamID `json:"Stream,omitempty"`
}

type ArrayWriterConn struct {
	io.WriteCloser
	aw     *ArrayWriter
	connID []byte
}

// Every time ArratWriterConn.Write is called
// We see a new qlog entry with the \n as the value.
func (awc *ArrayWriterConn) Write(p []byte) (n int, err error) {
	trimmedData := bytes.Trim(p, "\n")
	if len(trimmedData) > 0 {
		awc.aw.AddKV(&KV{Name: "qlog", Value: string(p), Conn: awc.connID})
	}
	return len(p), nil
}

func (awc *ArrayWriterConn) Close() error {
	return nil
}

type KeyLogWriter struct {
	aw *ArrayWriter
}

func (klw KeyLogWriter) Write(p []byte) (n int, err error) {
	klw.aw.AddKV(&KV{Name: "keylog", Value: string(p)})
	return len(p), nil
}

type ArrayWriter struct {
	array        []interface{}
	mutex        sync.Mutex
	canBeWritten bool
}

func NewArrayWriter() *ArrayWriter {
	return &ArrayWriter{
		canBeWritten: true,
	}
}

func (aw *ArrayWriter) ForConn(_ logging.Perspective, connID []byte) io.WriteCloser {
	return &ArrayWriterConn{
		aw:     aw,
		connID: connID,
	}
}

func (aw *ArrayWriter) AddTypeConn(i interface{}, connID []byte) {
	aw.AddKV(&KV{Name: fmt.Sprintf("%T", i), Value: i, Conn: connID})
}

// Our custom key value pair to log custom fields.
// TODO: Log Hexadecimal string directly for versions
// Currently decimal representation of version is logged.
func (aw *ArrayWriter) AddCustomKeyValue(key string, value interface{}, connID []byte) {
	aw.AddKV(&KV{Name: key, Value: value, Conn: connID})
}

func (aw *ArrayWriter) AddTypeConnStream(i interface{}, connID []byte, stream logging.StreamID) {
	aw.AddKV(&KV{Name: fmt.Sprintf("%T", i), Value: i, Conn: connID, Stream: &stream})
}

func (aw *ArrayWriter) AddType(i interface{}) {
	aw.AddKV(&KV{Name: fmt.Sprintf("%T", i), Value: i})
}

func (aw *ArrayWriter) AddKV(kv *KV) {
	aw.mutex.Lock()
	defer aw.mutex.Unlock()
	if aw.canBeWritten {
		aw.array = append(aw.array, kv)
	}
}

func (aw *ArrayWriter) Add(name string, i interface{}) {
	aw.AddKV(&KV{Name: name, Value: i})
}

func (aw *ArrayWriter) GetArray() []interface{} {
	aw.mutex.Lock()
	defer aw.mutex.Unlock()
	aw.canBeWritten = false
	return aw.array
}

type ourRequest struct {
	*http.Request
	//hack to ignore fields, such that the marshaller is happy
	GetBody  int `json:",omitempty"`
	Cancel   int `json:",omitempty"`
	Response int `json:",omitempty"`
}

type ourResponse struct {
	*http.Response
	BodySha256 string `json:",omitempty"`
	BodyLength int64
	Body       string `json:",omitempty"`
	Request    ourRequest
}

func readToHash(flags *Flags, res *http.Response) (length int64, body string, hash []byte) {
	readLen := int64(flags.MaxSize) * 1024
	if res.ContentLength >= 0 && res.ContentLength < readLen {
		readLen = res.ContentLength
	}
	if readLen == 0 {
		return 0, "", nil
	}

	b := new(bytes.Buffer)
	length, _ = io.CopyN(b, res.Body, readLen)
	body = b.String()

	if length > 0 {
		m := sha256.New()
		m.Write(b.Bytes())
		hash = m.Sum(nil)
	}
	return length, body, hash
}

func (aw *ArrayWriter) AddResponse(kind string, resp *http.Response, flags *Flags) {
	length, _, hash := readToHash(flags, resp)
	// Close the Body (IOStream). We are not using the body.
	// Hence, we are not storing the http/3 response body.
	// This saves output file size. We have similar option for http scan.
	if !flags.SaveH3Body {
		resp.Body.Close()
	}
	// Set the TLS field to nil, if you dont want to log TLS information of H3 response.
	// It includes DidResume, NegotiatedProtocol, PeerCertificates etc.
	// We will not store this in our result, since it contains invalid data types for our DB processing.
	// TLS info might be useful to see 0-RTT connections, Enrypted SNI or Ecnrypted Client Hello.
	if !flags.SaveH3TLS {
		resp.TLS = nil
	}

	or := ourResponse{
		Response: resp, BodySha256: hex.EncodeToString(hash),
		BodyLength: length, Request: ourRequest{Request: resp.Request},
	}
	aw.Add(kind, or)
}

type ourUDPAddr struct {
	net.UDPAddr
	Addr string
}

// getDial returns our custom dial function for creating QUIC connections.
// In this function we create a UDP connection and pass it to the QUIC transport.
// Meanwhile, we filter the blocked address and log the first remote address of the UDP connection.
// This is usefull to get the remote IP address which is talking QUIC.
// Since we do not use UDPDial, it is not guranteed that the remote address is same as the first address we resolved
// As a fix and confirmation , Use "dst_ip" from transport:connection_started qlog to get remote IP address.
func getDial(flags *Flags, target *zgrab2.ScanTarget, aw *ArrayWriter) func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
		host, svc, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		// Use fixed IP if available and request is for target domain
		resolver := net.DefaultResolver
		if target.IP != nil && host == target.Domain {
			if r, err := zgrab2.NewFakeResolver(target.IP.String()); err != nil {
				return nil, err
			} else {
				resolver = r
			}
		}

		// See quic.dialAddrContext
		// network is always "udp" for h3
		network := "udp"
		ips, err := blocklist.LookupIP(resolver, ctx, target.IPNetwork(), host)
		if err != nil {
			return nil, err
		}
		port, err := resolver.LookupPort(ctx, network, svc)
		if err != nil {
			return nil, err
		}
		udpAddr := net.UDPAddr{IP: ips[0], Port: port}
		aw.Add("remote-addr", &ourUDPAddr{UDPAddr: udpAddr, Addr: addr})

		// We do not use net.DialUDP, if used we need to handle WirteTo function in quic-go library.
		// Error "use of WriteTo with pre-connected connection" will occur if Dial is used
		// wihout handling preconnected connection.
		// However, we use Dial function to filter IP address and log remote address.
		// Also, logging remote address from qlog to get the remote IP address which is talking QUIC.
		// udpConn, err := net.DialUDP(network, &net.UDPAddr{IP: net.IPv4zero, Port: 0}, &udpAddr)

		// ListenUDP will just create a UDP socket and bind it to the given address to listent incoming packets.
		udpConn, err := net.ListenUDP(network, &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return nil, err
		}

		// Create QUIC transport with the UDP connection
		tr := quic.Transport{
			Conn: udpConn,
		}

		// Dials a new QUIC connection, attempting to use 0-RTT if possible
		// (never possible, Since we dont know anything about QUIC server).
		// This is used to satisfy the quic.Dialer interface.
		return tr.DialEarly(ctx, &udpAddr, tlsCfg, cfg)
	}
}

func getCheckRedirect(flags *Flags, aw *ArrayWriter) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		aw.AddResponse("redirect", req.Response, flags)

		// flags.MaxRedirects defaults to 0, i.e., no redirects at all.
		// We mirror the behavior of the non-h3 http scanner.
		if len(via) > flags.MaxRedirects {
			return ErrTooManyH3Redirects
		}

		if req.URL.User != nil {
			return ErrRedirectWithCreds
		}

		return nil
	}
}

func QuicRequest(target *zgrab2.ScanTarget, addr string, flags *Flags) interface{} {
	aw := NewArrayWriter()

	// qlog
	qTracer := func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
		// default qlog tracer for connection
		defaultTracer := qlog.NewConnectionTracer(aw.ForConn(p, connID.Bytes()), p, connID)
		// custom logging: Add seperate entry for required packets to json log for easier processing.
		customTracer := &logging.ConnectionTracer{
			// Add connnection started packet by logging dst_ip (remote address, alternate for Dial).
			StartedConnection: func(local, remote net.Addr, srcConnID, destConnID logging.ConnectionID) {
				aw.AddCustomKeyValue("Remote_Address", remote, destConnID.Bytes())
			},
			// Add version negotiation packet by logging server offered versions.
			ReceivedVersionNegotiationPacket: func(dest, src logging.ArbitraryLenConnectionID, offeredVersions []logging.VersionNumber) {
				// TODO: Log Hexadecimal string directly for versions
				aw.AddCustomKeyValue("Offered_Versions", offeredVersions, dest)
			},
			// Add server advertised transport parameters.
			ReceivedTransportParameters: func(tp *logging.TransportParameters) {
				aw.AddCustomKeyValue("Received_TP", tp, nil)
			},
			// Log Long Header QUIC bit, to check if server does greasing. (We do not log Short Header QUIC bit, due issue in processing)
			ReceivedLongHeaderPacket: func(eh *logging.ExtendedHeader, bc logging.ByteCount, e logging.ECN, f []logging.Frame) {
				aw.AddCustomKeyValue("Received_LH_QuicBit", eh.Header.QuicBit, nil)
			},
			// ADD connection closed packet by logging close reason.
			ClosedConnection: func(err error) {
				aw.AddCustomKeyValue("Close_Reason", err, nil)
			},
		}
		return logging.NewMultiplexedConnectionTracer(defaultTracer, customTracer)
	}

	// TODO: Take from module flags
	// QUIC version : Pick version based on test,
	// QUICv1 - 0x1 To test QUICv1
	// QUICv2 - 0x6b3343cf To test QUICv2
	// QUICvIN - 0x3 To elicit version negotiation
	var quicVersion = []quic.VersionNumber{
		0x1,
	}

	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !flags.TLSFlags.VerifyServerCertificate,
			KeyLogWriter:       KeyLogWriter{aw},
		},
		QuicConfig: &quic.Config{
			Tracer:                 qTracer,
			HandshakeIdleTimeout:   5000 * time.Millisecond,
			Versions:               quicVersion,
			DisableQUICBitGreasing: true, // false when testing greasing, true by default.
			// ECNMode:              ecnMode,
		},
		Dial: getDial(flags, target, aw),
	}
	// keep this in case of panics
	defer roundTripper.Close()

	hclient := &http.Client{
		Timeout:       flags.Timeout,
		Transport:     roundTripper,
		CheckRedirect: getCheckRedirect(flags, aw),
	}

	aw.Add("url", addr)

	get := func(client *http.Client, url string) (resp *http.Response, err error) {
		req, err := http.NewRequest(flags.Method, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "*/*")
		req.Header.Add("Priority", "u=5, i")
		req.Header.Add("user-agent", flags.UserAgent)
		resp, err = client.Do(req)
		return resp, err
	}
	resp, err := get(hclient, addr)
	if err == nil {
		aw.AddResponse("*http.Response", resp, flags)
	}

	// Explicitly close connections to allow logging into aw
	// The deferred roundTripper.Close() call becomes a no-op
	if closeErr := roundTripper.Close(); closeErr != nil {
		aw.Add("close_error", fmt.Sprint(closeErr))
	}
	if err != nil {
		aw.Add("error", fmt.Sprint(err))
	}
	return aw.GetArray()
}
