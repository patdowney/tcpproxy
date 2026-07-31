package tcpproxy

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
)

// sniPeekBufferSize bounds how much of the client's plaintext negotiation
// and subsequent TLS ClientHello can be buffered/peeked. It's sized above
// the TLS spec's maximum plaintext record length (16384 bytes) so a
// ClientHello with many extensions (common with modern/enterprise mail
// senders) doesn't overflow Peek and get silently treated as "no SNI" by
// clientHelloServerName in sni.go.
const sniPeekBufferSize = 20 * 1024

func greetSMTP(r *textproto.Reader, w *textproto.Writer, serverName string) (string, error) {
	w.PrintfLine("220 %s Service ready", serverName)
	l, e := r.ReadLine() // "EHLO <client-name>
	if e != nil {
		return "", e
	}

	var clientName string
	_, e = fmt.Sscanf(l, "EHLO %s", &clientName)
	if e != nil {
		return "", e
	}

	return clientName, nil
}

func negotiateSMTPTLS(r *textproto.Reader, w *textproto.Writer, smtpServerName string) error {
	w.PrintfLine("250-%s G'day!", smtpServerName)
	w.PrintfLine("250 STARTTLS")
	cmd, err := r.ReadLine() // "STARTTLS"
	if err != nil {
		return err
	}
	if cmd != "STARTTLS" {
		return fmt.Errorf("expecting STARTTLS, got %q", cmd)
	}

	w.PrintfLine("220 Go ahead")
	return nil
}

func negotiateSMTPStartTLS(serverName string) NegotiateFunc {
	return func(c net.Conn, cfg *config) (*bufio.Reader, bool) {
		// Negotiate STARTTLS over a single, larger-than-default buffered
		// reader, and hand that same reader back on success so route
		// matching (the SNI peek in sni.go) continues reading from it
		// instead of a fresh bufio.Reader(c). Without this, any bytes the
		// client pipelines immediately after "STARTTLS" (e.g. its TLS
		// ClientHello, sent before waiting for "220 Go ahead") would be
		// silently absorbed into the negotiation reader's buffer and lost
		// when a new reader was created for the peek step.
		br := bufio.NewReaderSize(c, sniPeekBufferSize)
		r := textproto.NewReader(br)
		w := textproto.NewWriter(bufio.NewWriter(c))

		_, err := greetSMTP(r, w, serverName)
		if err == nil {
			if err := negotiateSMTPTLS(r, w, serverName); err == nil {
				return br, true
			}
		}
		c.Close()
		return nil, false
	}
}
