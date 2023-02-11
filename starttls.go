package tcpproxy

import (
	"errors"
	"fmt"
	"net"
	"net/textproto"
)

func greetSMTP(c *textproto.Conn, serverName string) (string, error) {
	var clientName string
	c.Writer.PrintfLine("220 %s Service ready", serverName)
	l, e := c.ReadLine() // "EHLO <client-name>
	if e != nil {
		return "", e
	}
	n, e := fmt.Sscanf(l, "EHLO %s", &clientName)
	if e != nil {
		return "", e
	}
	if n != 1 {
		return "", errors.New("could not read client name from EHLO")
	}
	return clientName, nil
}

func negotiateSMTPTLS(c *textproto.Conn, smtpServerName string) error {
	c.Writer.PrintfLine("250-%s G'day!", smtpServerName)
	c.Writer.PrintfLine("250 STARTTLS")
	cmd, err := c.ReadLine() // "STARTTLS"
	if err == nil {
		if cmd == "STARTTLS" {
			c.Writer.PrintfLine("220 Go ahead")
			return nil
		}
		return errors.New("expecting STARTTLS")
	}

	return err
}

func negotiateSMTPStartTLS(serverName string) NegotiateFunc {
	return func(c net.Conn, cfg *config) bool {
		// negotiate STARTTLS
		t := textproto.NewConn(c)
		_, err := greetSMTP(t, serverName)
		if err == nil {
			err := negotiateSMTPTLS(t, cfg.smtpServerName)
			if err == nil {
				return true
			}
		}
		t.Close()
		return false
	}
}
