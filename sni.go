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
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"

	"github.com/google/uuid"
)

// AddSNIRoute appends a route to the ipPort listener that routes to
// dest if the incoming TLS SNI server name is sni. If it doesn't
// match, rule processing continues for any additional routes on
// ipPort.
//
// The ipPort is any valid net.Listen TCP address.
func (p *Proxy) AddSNIRoute(ipPort, sni string, dest Target) uuid.UUID {
	return p.AddSNIMatchRoute(ipPort, equals(sni), dest)
}

// DynamicTarget Deprecated
type DynamicTarget func(ctx context.Context, hostname string) (Target, error)

// AddSNIDynamicRoute No ACME, ACME challenge/response expected to be done at other end
func (p *Proxy) AddSNIDynamicRoute(ipPort string, targetLookup DynamicTarget) uuid.UUID {
	return p.addRoute(ipPort, dynamicSNIMatch{dynMatcher: targetLookup})
}

// AddSNIMatchRoute appends a route to the ipPort listener that routes
// to dest if the incoming TLS SNI server name is accepted by
// matcher. If it doesn't match, rule processing continues for any
// additional routes on ipPort.
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

	p.addRouteWithId(ipPort, sniMatch{matcher, dest, nil}, routeId)

	return routeId
}

// AddSNIDynamicSMTPRoute
func (p *Proxy) AddSNIDynamicSMTPRoute(ipPort string, serverName string, targetLookup DynamicTarget) uuid.UUID {
	cfg := p.configFor(ipPort)
	cfg.negotiateFunc = negotiateSMTPStartTLS(serverName)

	return p.addRoute(ipPort, dynamicSNIMatch{dynMatcher: targetLookup})
}

// SNITargetFunc is the func callback used by Proxy.AddSNIRouteFunc.
type SNITargetFunc func(ctx context.Context, sniName string) (t Target, ok bool)

// AddSNIRouteFunc adds a route to ipPort that matches an SNI request and calls
// fn to map its nap to a target.
func (p *Proxy) AddSNIRouteFunc(ipPort string, fn SNITargetFunc) uuid.UUID {
	return p.addRoute(ipPort, sniMatch{targetFunc: fn})
}

type dynamicSNIMatch struct {
	dynMatcher DynamicTarget
}

func (m dynamicSNIMatch) match(br peeker) (Target, string) {
	sni := clientHelloServerName(br)

	if m.dynMatcher == nil {
		return nil, ""

	}

	target, err := m.dynMatcher(context.TODO(), sni)
	if err != nil {
		return nil, ""
	}

	return target, sni
}

type sniMatch struct {
	matcher Matcher
	target  Target

	// Alternatively, if targetFunc is non-nil, it's used instead:
	targetFunc SNITargetFunc
}

func (m sniMatch) match(br peeker) (Target, string) {
	sni := clientHelloServerName(br)
	if sni == "" {
		return nil, ""
	}
	if m.targetFunc != nil {
		if t, ok := m.targetFunc(context.TODO(), sni); ok {
			return t, sni
		}
		return nil, ""
	}
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

func (m *acmeMatch) match(br peeker) (Target, string) {
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
func clientHelloServerName(br peeker) (sni string) {
	hello, err := ReadClientHelloInfo(br)
	if err != nil {
		return ""
	}

	return hello.ServerName
}

func clientEhloServerName(c net.Conn) (sni string) {
	ehlo, err := ReadEhloAndStartTLS(c)
	if err != nil {
		return ""
	}
	return ehlo
}

func ReadEhloAndStartTLS(c net.Conn) (string, error) {
	//r := bufio.NewReader(c)
	//w := bufio.NewWriter(c)
	//rw := bufio.NewReadWriter(r, w)

	t := textproto.NewConn(c)

	l, err := t.ReadLine()
	if err != nil {
		return "", nil
	}
	//t.ReadCodeLine()
	//rw.WriteString("asdf\r")

	//r.ReadString('\r')
	return l, nil
}

func ReadClientHelloInfo(br peeker) (*tls.ClientHelloInfo, error) {

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
