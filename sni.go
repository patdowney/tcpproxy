// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcpproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/google/uuid"
)

// AddSNIRoute appends a route to the ipPort listener that routes to
// dest if the incoming TLS SNI server name is sni. If it doesn't
// match, rule processing continues for any additional routes on
// ipPort.
//
// By default, the proxy will route all ACME tls-sni-01 challenges
// received on ipPort to all SNI dests. You can disable ACME routing
// with AddStopACMESearch.
//
// The ipPort is any valid net.Listen TCP address.
func (p *Proxy) AddSNIRoute(ipPort, sni string, dest Target) uuid.UUID {
	return p.AddSNIMatchRoute(ipPort, equals(sni), dest)
}

// No ACME, ACME challenge/response expected to be done at other end
func (p *Proxy) AddSNIDynamicRoute(ipPort string, targetLookup TargetLookup) uuid.UUID {
	return p.addRoute(ipPort, dynamicSNIMatch{dynMatcher: targetLookup})
}

// AddSNIMatchRoute appends a route to the ipPort listener that routes
// to dest if the incoming TLS SNI server name is accepted by
// matcher. If it doesn't match, rule processing continues for any
// additional routes on ipPort.
//
// By default, the proxy will route all ACME tls-sni-01 challenges
// received on ipPort to all SNI dests. You can disable ACME routing
// with AddStopACMESearch.
//
// The ipPort is any valid net.Listen TCP address.
func (p *Proxy) AddSNIMatchRoute(ipPort string, matcher Matcher, dest Target) uuid.UUID {
	routeId := uuid.New()

	cfg := p.configFor(ipPort)
	if !cfg.stopACME {
		if len(cfg.acmeTargets) == 0 {
			p.addRouteWithId(ipPort, &acmeMatch{cfg}, routeId)
		}
		cfg.acmeTargets = append(cfg.acmeTargets, dest)
	}

	p.addRouteWithId(ipPort, sniMatch{matcher, dest}, routeId)

	return routeId
}

// AddStopACMESearch prevents ACME probing of subsequent SNI routes.
// Any ACME challenges on ipPort for SNI routes previously added
// before this call will still be proxied to all possible SNI
// backends.
func (p *Proxy) AddStopACMESearch(ipPort string) {
	p.configFor(ipPort).stopACME = true
}

type dynamicSNIMatch struct {
	dynMatcher TargetLookup
}

func (m dynamicSNIMatch) match(br *bufio.Reader) (Target, string) {
	sni := clientHelloServerName(br)

	if m.dynMatcher == nil {
		return nil, ""

	}

	targetAddr, err := m.dynMatcher(context.TODO(), sni)
	if err != nil {
		return nil, ""
	}

	return To(targetAddr), sni
}

type sniMatch struct {
	matcher Matcher
	target  Target
}

func (m sniMatch) match(br *bufio.Reader) (Target, string) {
	sni := clientHelloServerName(br)
	if m.matcher(context.TODO(), sni) {
		return m.target, sni
	}
	return nil, ""
}

// acmeMatch matches "*.acme.invalid" ACME tls-sni-01 challenges and
// searches for a Target in cfg.acmeTargets that has the challenge
// response.
type acmeMatch struct {
	cfg *config
}

func (m *acmeMatch) match(br *bufio.Reader) (Target, string) {
	sni := clientHelloServerName(br)
	if !strings.HasSuffix(sni, ".acme.invalid") {
		return nil, ""
	}

	// TODO: cache. ACME issuers will hit multiple times in a short
	// burst for each issuance event. A short TTL cache + singleflight
	// should have an excellent hit rate.
	// TODO: maybe an acme-specific timeout as well?
	// TODO: plumb context upwards?
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan Target, len(m.cfg.acmeTargets))
	for _, target := range m.cfg.acmeTargets {
		go tryACME(ctx, ch, target, sni)
	}
	for range m.cfg.acmeTargets {
		if target := <-ch; target != nil {
			return target, sni
		}
	}

	// No target was happy with the provided challenge.
	return nil, ""
}

func tryACME(ctx context.Context, ch chan<- Target, dest Target, sni string) {
	var ret Target
	defer func() { ch <- ret }()

	conn, targetConn := net.Pipe()
	defer conn.Close()
	go dest.HandleConn(targetConn)

	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	client := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	if err := client.Handshake(); err != nil {
		// TODO: log?
		return
	}
	certs := client.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		// TODO: log?
		return
	}
	// acme says the first cert offered by the server must match the
	// challenge hostname.
	if err := certs[0].VerifyHostname(sni); err != nil {
		// TODO: log?
		return
	}

	// Target presented what looks like a valid challenge
	// response, send it back to the matcher.
	ret = dest
}

// clientHelloServerName returns the SNI server name inside the TLS ClientHello,
// without consuming any bytes from br.
// On any error, the empty string is returned.
func clientHelloServerName(br *bufio.Reader) (sni string) {
	hello, err := ReadClientHelloInfo(br)
	if err != nil {
		return ""
	}

	return hello.ServerName
}

func ReadClientHelloInfo(br *bufio.Reader) (*tls.ClientHelloInfo, error) {

	const recordHeaderLen = 5
	hdr, err := br.Peek(recordHeaderLen)
	if err != nil {
		return nil, err
	}
	const recordTypeHandshake = 0x16
	if hdr[0] != recordTypeHandshake {
		return nil, fmt.Errorf("not tls")
	}
	recLen := int(hdr[3])<<8 | int(hdr[4]) // ignoring version in hdr[1:3]
	helloBytes, err := br.Peek(recordHeaderLen + recLen)
	if err != nil {
		return nil, err
	}

	helloInfo := &tls.ClientHelloInfo{}
	tls.Server(sniSniffConn{r: bytes.NewReader(helloBytes)}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			helloInfo = hello
			return nil, nil
		},
	}).Handshake()
	return helloInfo, nil
}

// sniSniffConn is a net.Conn that reads from r, fails on Writes,
// and crashes otherwise.
type sniSniffConn struct {
	r        io.Reader
	net.Conn // nil; crash on any unexpected use
}

func (c sniSniffConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (sniSniffConn) Write(p []byte) (int, error)  { return 0, io.EOF }
