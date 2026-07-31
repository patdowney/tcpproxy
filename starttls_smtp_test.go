package tcpproxy

import (
	"bufio"
	"io"
	"net"
	"testing"
)

// TestSMTPStartTLSPipelinedClientHello reproduces the byte pattern seen from
// real-world senders that don't wait for "220 Go ahead" before starting
// their TLS handshake: the TLS ClientHello arrives in the same write as (or
// immediately after) "STARTTLS\r\n". Before the fix, those extra bytes were
// buffered by the negotiation's own textproto reader and lost when route
// matching created a brand new bufio.Reader over the raw conn, causing the
// SNI peek to see nothing and the connection to be dropped.
func TestSMTPStartTLSPipelinedClientHello(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	const hostName = "bar.com"
	clientHello := clientHelloRecord(t, hostName)

	clientErrc := make(chan error, 1)
	go func() {
		r := bufio.NewReader(client)
		err := func() error {
			if _, err := r.ReadString('\n'); err != nil { // "220 ... Service ready"
				return err
			}
			if _, err := io.WriteString(client, "EHLO test.local\r\n"); err != nil {
				return err
			}
			if _, err := r.ReadString('\n'); err != nil { // "250-... G'day!"
				return err
			}
			if _, err := r.ReadString('\n'); err != nil { // "250 STARTTLS"
				return err
			}
			// Pipeline STARTTLS and the ClientHello in a single write,
			// without waiting for "220 Go ahead" first.
			_, err := io.WriteString(client, "STARTTLS\r\n"+clientHello)
			return err
		}()
		clientErrc <- err
		// Drain (and discard) the "220 Go ahead" response: real clients
		// that pipeline like this have already moved on to the TLS
		// handshake and never read it. Without draining it here, the
		// server-side write would block forever against net.Pipe's
		// synchronous semantics (a real socket has OS send buffering and
		// wouldn't need this).
		_, _ = io.Copy(io.Discard, r)
	}()

	negotiate := negotiateSMTPStartTLS("test.local")
	br, ok := negotiate(server, &config{})
	if !ok {
		t.Fatal("negotiation failed")
	}
	if err := <-clientErrc; err != nil {
		t.Fatalf("client side failed: %v", err)
	}
	if br == nil {
		t.Fatal("expected negotiation to return the buffered reader it used")
	}

	sni := clientHelloServerName(br)
	if sni != hostName {
		t.Fatalf("got SNI %q after a pipelined ClientHello; want %q (bytes were lost across the negotiation/peek handoff)", sni, hostName)
	}
}
