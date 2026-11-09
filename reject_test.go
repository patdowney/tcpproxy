package tcpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// rejection is one OnReject call.
type rejection struct {
	listenAddr string
	reason     RejectReason
}

// recordRejections sets p.OnReject to send each call to the returned channel.
func recordRejections(p *Proxy) <-chan rejection {
	got := make(chan rejection, 4)
	p.OnReject = func(listenAddr string, reason RejectReason) {
		got <- rejection{listenAddr, reason}
	}
	return got
}

// expectRejection fails unless the proxy reports want for testFrontAddr.
func expectRejection(t *testing.T, got <-chan rejection, want RejectReason) {
	t.Helper()
	select {
	case r := <-got:
		if r != (rejection{testFrontAddr, want}) {
			t.Fatalf("OnReject(%q, %q); want (%q, %q)", r.listenAddr, r.reason, testFrontAddr, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no OnReject call; want %q", want)
	}
}

// anonymousClientHello returns a TLS ClientHello that names no server.
func anonymousClientHello(t *testing.T) string {
	t.Helper()
	rec := new(recordWritesConn)
	_ = tls.Client(rec, &tls.Config{InsecureSkipVerify: true}).Handshake() // #nosec G402 -- only the ClientHello bytes are used
	if rec.buf.Len() == 0 {
		t.Fatal("no ClientHello written")
	}
	return rec.buf.String()
}

// smtpClient drives the client side of the edge's pre-TLS SMTP exchange.
type smtpClient struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

// expect reads n response lines, ignoring their content.
func (c *smtpClient) expect(n int) {
	c.t.Helper()
	for range n {
		if _, err := c.r.ReadString('\n'); err != nil {
			c.t.Fatalf("reading response: %v", err)
		}
	}
}

func (c *smtpClient) send(s string) {
	c.t.Helper()
	if _, err := io.WriteString(c.conn, s); err != nil {
		c.t.Fatalf("writing %q: %v", s, err)
	}
}

// startTLS greets the edge and asks for STARTTLS, as a TLS sender does.
func (c *smtpClient) startTLS() {
	c.t.Helper()
	c.expect(1) // 220 greeting
	c.send("EHLO client.example\r\n")
	c.expect(2) // 250-..., 250 STARTTLS
	c.send("STARTTLS\r\n")
	c.expect(1) // 220 Go ahead
}

func TestOnRejectReportsWhySMTPConnectionsAreDropped(t *testing.T) {
	tests := []struct {
		name   string
		client func(c *smtpClient)
		// keepOpen leaves the connection open until the proxy reports.
		keepOpen bool
		want     RejectReason
	}{
		{
			name: "plaintext sender skips STARTTLS",
			client: func(c *smtpClient) {
				c.expect(1)
				c.send("EHLO client.example\r\n")
				c.expect(2)
				c.send("MAIL FROM:<a@client.example>\r\n")
			},
			want: RejectNoStartTLS,
		},
		{
			name: "HELO sender can't start TLS",
			client: func(c *smtpClient) {
				c.expect(1)
				c.send("HELO client.example\r\n")
			},
			want: RejectNoStartTLS,
		},
		{
			name:   "sender disconnects after the greeting",
			client: func(c *smtpClient) { c.expect(1) },
			want:   RejectNegotiationFailed,
		},
		{
			name:     "sender goes quiet",
			client:   func(*smtpClient) {},
			keepOpen: true,
			want:     RejectHandshakeTimeout,
		},
		{
			name:   "no ClientHello after STARTTLS",
			client: func(c *smtpClient) { c.startTLS() },
			want:   RejectNoData,
		},
		{
			name: "plaintext after STARTTLS",
			client: func(c *smtpClient) {
				c.startTLS()
				c.send("MAIL FROM:<a@client.example>\r\n")
			},
			want: RejectNotTLS,
		},
		{
			name: "ClientHello without SNI",
			client: func(c *smtpClient) {
				c.startTLS()
				c.send(anonymousClientHello(t))
			},
			want: RejectNoSNI,
		},
		{
			name: "ClientHello for an unknown host",
			client: func(c *smtpClient) {
				c.startTLS()
				c.send(clientHelloRecord(t, "unknown.example"))
			},
			want: RejectNoRoute,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			front := newLocalListener(t)
			defer front.Close()

			p := testProxy(t, front)
			p.HandshakeTimeout = 200 * time.Millisecond
			got := recordRejections(p)
			p.AddSMTPSNIRouteFunc(testFrontAddr, "mx.test", func(_ context.Context, sni string) (Target, bool) {
				return noopTarget{}, sni == "known.example"
			})
			if err := p.Start(); err != nil {
				t.Fatal(err)
			}
			defer p.Close()

			conn, err := net.Dial("tcp", front.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			tt.client(&smtpClient{t: t, conn: conn, r: bufio.NewReader(conn)})
			if tt.keepOpen {
				defer conn.Close()
			} else {
				conn.Close()
			}

			expectRejection(t, got, tt.want)
		})
	}
}

func TestOnRejectReportsConnectionsOverCapacity(t *testing.T) {
	front := newLocalListener(t)
	defer front.Close()

	p := testProxy(t, front)
	p.MaxConnections = 1
	got := recordRejections(p)
	// An SNI route waits for a ClientHello, so a silent client holds the
	// only slot.
	p.AddSNIRoute(testFrontAddr, "example.com", noopTarget{})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	first, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	expectRejection(t, got, RejectOverCapacity)
}

// TestOnRejectClosesAtOnceOnAListenerWithNoRoutes pins that a listener
// whose routes have all been removed, as when a tunnel disconnects, closes a
// silent client straight away rather than waiting for it to send something.
func TestOnRejectClosesAtOnceOnAListenerWithNoRoutes(t *testing.T) {
	front := newLocalListener(t)
	defer front.Close()

	p := testProxy(t, front)
	got := recordRejections(p)
	p.RemoveRouteById(testFrontAddr, p.AddSNIRoute(testFrontAddr, "example.com", noopTarget{}))
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	conn, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	expectClosedWithin(t, conn, time.Second)
	expectRejection(t, got, RejectNoRoute)
}

func TestOnRejectIsNotCalledForRoutedConnections(t *testing.T) {
	front := newLocalListener(t)
	defer front.Close()

	p := testProxy(t, front)
	got := recordRejections(p)
	routed := make(chan struct{})
	p.AddSNIRoute(testFrontAddr, "example.com", targetFunc(func(c net.Conn) {
		close(routed)
		c.Close()
	}))
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	conn, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, clientHelloRecord(t, "example.com")); err != nil {
		t.Fatal(err)
	}

	select {
	case <-routed:
	case <-time.After(5 * time.Second):
		t.Fatal("connection was not routed")
	}
	select {
	case r := <-got:
		t.Fatalf("OnReject(%q, %q) for a routed connection", r.listenAddr, r.reason)
	case <-time.After(50 * time.Millisecond):
	}
}

// targetFunc adapts a function to a Target.
type targetFunc func(net.Conn)

func (f targetFunc) HandleConn(c net.Conn) { f(c) }
