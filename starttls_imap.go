package tcpproxy

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
	"strings"
)

// imapCapabilities is what the pre-TLS front end offers: STARTTLS, and no
// login until the connection is upgraded and handed to the real server.
const imapCapabilities = "IMAP4rev1 STARTTLS LOGINDISABLED"

// maxIMAPPreTLSCommands bounds how many commands a client may send before
// STARTTLS, so a connection can't be held open in the plaintext stage.
const maxIMAPPreTLSCommands = 8

// negotiateIMAPTLS answers commands until the client asks for STARTTLS.
// Clients commonly send CAPABILITY first, to confirm STARTTLS is offered,
// and some send NOOP; both are answered. LOGOUT ends the connection, and
// anything else gets BAD, as it can't be served before TLS.
func negotiateIMAPTLS(r *textproto.Reader, w *textproto.Writer) error {
	if err := w.PrintfLine("* OK [CAPABILITY %s] IMAP4rev1 Service Ready", imapCapabilities); err != nil {
		return err
	}

	for range maxIMAPPreTLSCommands {
		line, err := r.ReadLine()
		if err != nil {
			return err
		}

		tag, rest, found := strings.Cut(line, " ")
		if !found {
			return fmt.Errorf("malformed command line %q", line)
		}
		cmd, _, _ := strings.Cut(rest, " ")

		switch strings.ToUpper(cmd) {
		case "STARTTLS":
			return w.PrintfLine("%s OK Begin TLS negotiation now", tag)
		case "CAPABILITY":
			if err := w.PrintfLine("* CAPABILITY %s", imapCapabilities); err != nil {
				return err
			}
			if err := w.PrintfLine("%s OK CAPABILITY completed", tag); err != nil {
				return err
			}
		case "NOOP":
			if err := w.PrintfLine("%s OK NOOP completed", tag); err != nil {
				return err
			}
		case "LOGOUT":
			_ = w.PrintfLine("* BYE Logging out")
			_ = w.PrintfLine("%s OK LOGOUT completed", tag)
			return fmt.Errorf("%w: client logged out", ErrNoStartTLS)
		default:
			if err := w.PrintfLine("%s BAD %s is not available before STARTTLS", tag, cmd); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("%w: no STARTTLS after %d commands", ErrNoStartTLS, maxIMAPPreTLSCommands)
}

func negotiateIMAPStartTLS() NegotiateFunc {
	return func(c net.Conn, cfg *config) (*bufio.Reader, error) {
		// See negotiateSMTPStartTLS in starttls_smtp.go for why the
		// negotiation reader is sized above the default 4096 bytes and
		// reused for the subsequent SNI peek instead of discarded.
		br := bufio.NewReaderSize(c, sniPeekBufferSize)
		r := textproto.NewReader(br)
		w := textproto.NewWriter(bufio.NewWriter(c))

		if err := negotiateIMAPTLS(r, w); err != nil {
			c.Close()
			return nil, err
		}
		return br, nil
	}
}
