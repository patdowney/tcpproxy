package tcpproxy

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// expectClosedWithin fails unless the proxy closes c within d: a Read must
// return an error (EOF or reset) rather than timing out on our own deadline.
func expectClosedWithin(t *testing.T, c net.Conn, d time.Duration) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatal(err)
	}
	_, err := c.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("read succeeded; want the proxy to close the connection")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("connection still open after %v; want the proxy to close it", d)
	}
}

func TestHandshakeTimeoutClosesSilentConn(t *testing.T) {
	front := newLocalListener(t)
	defer front.Close()

	p := testProxy(t, front)
	p.HandshakeTimeout = 100 * time.Millisecond
	// An SNI route must read a ClientHello before it can route, so a client
	// that sends nothing stalls in route matching.
	p.AddSNIRoute(testFrontAddr, "example.com", noopTarget{})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	c, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	expectClosedWithin(t, c, 5*time.Second)
}

func TestHandshakeTimeoutDoesNotLimitTheProxiedSession(t *testing.T) {
	front := newLocalListener(t)
	defer front.Close()
	back := newLocalListener(t)
	defer back.Close()

	p := testProxy(t, front)
	p.HandshakeTimeout = 50 * time.Millisecond
	p.AddRoute(testFrontAddr, To(back.Addr().String()))
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	toFront, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer toFront.Close()
	fromProxy, err := back.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer fromProxy.Close()

	// Stay idle well past the handshake timeout: the session must survive.
	time.Sleep(200 * time.Millisecond)
	const msg = "still here"
	if _, err := io.WriteString(toFront, msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if err := fromProxy.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(fromProxy, buf); err != nil {
		t.Fatalf("session cut after the handshake timeout: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("got %q; want %q", buf, msg)
	}
}

func TestMaxConnectionsClosesConnsBeyondTheLimit(t *testing.T) {
	front := newLocalListener(t)
	defer front.Close()
	back := newLocalListener(t)
	defer back.Close()

	p := testProxy(t, front)
	p.MaxConnections = 1
	p.AddRoute(testFrontAddr, To(back.Addr().String()))
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	first, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	firstBack, err := back.Accept()
	if err != nil {
		t.Fatal(err)
	}

	second, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	expectClosedWithin(t, second, 5*time.Second)

	// Ending the first session frees its slot for a new connection.
	first.Close()
	firstBack.Close()

	deadline := time.Now().Add(5 * time.Second)
	for {
		third, err := net.Dial("tcp", front.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		accepted := make(chan net.Conn, 1)
		go func() {
			if c, err := back.Accept(); err == nil {
				accepted <- c
			}
		}()
		select {
		case c := <-accepted:
			c.Close()
			third.Close()
			return
		case <-time.After(200 * time.Millisecond):
			third.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("slot was not released after the first session ended")
		}
	}
}
