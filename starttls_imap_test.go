package tcpproxy

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
)

// imapClient drives the client side of the pre-TLS IMAP exchange over a pipe.
type imapClient struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

func (c *imapClient) send(line string) {
	c.t.Helper()
	if _, err := io.WriteString(c.conn, line+"\r\n"); err != nil {
		c.t.Errorf("writing %q: %v", line, err)
	}
}

// readUntilTagged returns the lines up to and including the one starting
// with tag.
func (c *imapClient) readUntilTagged(tag string) []string {
	c.t.Helper()
	var lines []string
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Errorf("reading response to %s: %v", tag, err)
			return lines
		}
		lines = append(lines, strings.TrimRight(line, "\r\n"))
		if strings.HasPrefix(line, tag+" ") {
			return lines
		}
	}
}

// TestIMAPStartTLSAfterCapability pins the order real clients use: CAPABILITY
// first, to confirm STARTTLS is offered, then STARTTLS. The front end used to
// answer CAPABILITY with a non-standard "Unsupported command" line and close
// the connection, so curl and mail clients could never upgrade.
func TestIMAPStartTLSAfterCapability(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	const hostName = "mx.example.com"
	clientHello := clientHelloRecord(t, hostName)

	var capability, noop []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		c := &imapClient{t: t, conn: client, r: bufio.NewReader(client)}
		if _, err := c.r.ReadString('\n'); err != nil { // greeting
			t.Errorf("reading greeting: %v", err)
			return
		}
		c.send("A001 CAPABILITY")
		capability = c.readUntilTagged("A001")
		c.send("A002 noop")
		noop = c.readUntilTagged("A002")
		c.send("A003 STARTTLS")
		c.readUntilTagged("A003")
		if _, err := io.WriteString(client, clientHello); err != nil {
			t.Errorf("writing ClientHello: %v", err)
		}
	}()

	br, ok := negotiateIMAPStartTLS()(server, &config{})
	if !ok {
		t.Fatal("negotiation failed")
	}

	if got := clientHelloServerName(br); got != hostName {
		t.Fatalf("got SNI %q after STARTTLS; want %q", got, hostName)
	}
	<-done

	wantCapability := []string{"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED", "A001 OK CAPABILITY completed"}
	if strings.Join(capability, "\n") != strings.Join(wantCapability, "\n") {
		t.Errorf("CAPABILITY response = %q; want %q", capability, wantCapability)
	}
	if len(noop) != 1 || noop[0] != "A002 OK NOOP completed" {
		t.Errorf("NOOP response = %q; want the tagged OK (commands are case-insensitive)", noop)
	}
}

func TestIMAPStartTLSRefusals(t *testing.T) {
	tests := []struct {
		name     string
		commands []string
		wantLast string
	}{
		{
			name:     "LOGOUT ends the connection",
			commands: []string{"A001 LOGOUT"},
			wantLast: "A001 OK LOGOUT completed",
		},
		{
			name:     "other commands get BAD, then the client can still upgrade",
			commands: []string{"A001 LOGIN user pass"},
			wantLast: "A001 BAD LOGIN is not available before STARTTLS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()

			var last string
			done := make(chan struct{})
			go func() {
				defer close(done)
				c := &imapClient{t: t, conn: client, r: bufio.NewReader(client)}
				_, _ = c.r.ReadString('\n') // greeting
				for _, cmd := range tt.commands {
					c.send(cmd)
					lines := c.readUntilTagged(strings.Fields(cmd)[0])
					if len(lines) > 0 {
						last = lines[len(lines)-1]
					}
				}
				client.Close()
			}()

			if _, ok := negotiateIMAPStartTLS()(server, &config{}); ok {
				t.Fatal("negotiation succeeded without STARTTLS")
			}
			<-done
			if last != tt.wantLast {
				t.Errorf("last response = %q; want %q", last, tt.wantLast)
			}
		})
	}
}

// TestIMAPStartTLSCommandLimit pins that a client can't keep the plaintext
// stage open indefinitely.
func TestIMAPStartTLSCommandLimit(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		c := &imapClient{t: t, conn: client, r: bufio.NewReader(client)}
		_, _ = c.r.ReadString('\n')
		for i := range maxIMAPPreTLSCommands + 1 {
			tag := "A" + strings.Repeat("0", i+1)
			if _, err := io.WriteString(client, tag+" NOOP\r\n"); err != nil {
				return
			}
			if _, err := c.r.ReadString('\n'); err != nil {
				return
			}
		}
	}()

	if _, ok := negotiateIMAPStartTLS()(server, &config{}); ok {
		t.Fatalf("negotiation succeeded after %d commands without STARTTLS", maxIMAPPreTLSCommands)
	}
}
