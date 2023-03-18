package tcpproxy

import (
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
)

func negotiateIMAPTLS(c *textproto.Conn) error {
	c.Writer.PrintfLine("* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] IMAP4rev1 Service Ready")

	cmdString, err := c.ReadLine() // "STARTTLS"
	if err == nil {
		tag, cmd, found := strings.Cut(cmdString, " ")
		if !found {
			return errors.New("")
			return err
		}
		if cmd == "STARTTLS" {
			c.Writer.PrintfLine("%s OK Begin TLS negotiation now", tag)
			return nil
		}
		c.Writer.PrintfLine("%s %s Unsupported command", tag, cmd)
		return errors.New(fmt.Sprintf("unsupported command %s received", cmd))
	}

	return err
}

func negotiateIMAPStartTLS() NegotiateFunc {
	return func(c net.Conn, cfg *config) bool {
		// negotiate STARTTLS
		t := textproto.NewConn(c)

		err := negotiateIMAPTLS(t)
		if err == nil {
			return true
		}

		t.Close()
		return false
	}
}
