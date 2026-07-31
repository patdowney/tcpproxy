package tcpproxy

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
	"strings"
)

func negotiateIMAPTLS(r *textproto.Reader, w *textproto.Writer) error {
	w.PrintfLine("* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] IMAP4rev1 Service Ready")

	cmdString, err := r.ReadLine() // "STARTTLS"
	if err != nil {
		return err
	}

	tag, cmd, found := strings.Cut(cmdString, " ")
	if !found {
		return fmt.Errorf("malformed command line %q", cmdString)
	}
	if cmd == "STARTTLS" {
		w.PrintfLine("%s OK Begin TLS negotiation now", tag)
		return nil
	}
	w.PrintfLine("%s %s Unsupported command", tag, cmd)
	return fmt.Errorf("unsupported command %s received", cmd)
}

func negotiateIMAPStartTLS() NegotiateFunc {
	return func(c net.Conn, cfg *config) (*bufio.Reader, bool) {
		// See negotiateSMTPStartTLS in starttls_smtp.go for why the
		// negotiation reader is sized above the default 4096 bytes and
		// reused for the subsequent SNI peek instead of discarded.
		br := bufio.NewReaderSize(c, sniPeekBufferSize)
		r := textproto.NewReader(br)
		w := textproto.NewWriter(bufio.NewWriter(c))

		if err := negotiateIMAPTLS(r, w); err == nil {
			return br, true
		}

		c.Close()
		return nil, false
	}
}
