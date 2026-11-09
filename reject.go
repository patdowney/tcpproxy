package tcpproxy

import (
	"bufio"
	"errors"
	"net"
	"strconv"
	"strings"
)

// ErrNoStartTLS is returned by a STARTTLS negotiation when the client goes
// on without asking for TLS: it sent a mail or IMAP command, said HELO
// rather than EHLO, or logged out. Such a client wants to talk in plaintext.
var ErrNoStartTLS = errors.New("client did not start TLS")

// RejectReason says why the proxy closed an accepted connection without
// handing it to a Target.
type RejectReason string

const (
	// RejectOverCapacity: the proxy was already serving MaxConnections.
	RejectOverCapacity RejectReason = "over_capacity"
	// RejectHandshakeTimeout: negotiation or routing took longer than
	// HandshakeTimeout.
	RejectHandshakeTimeout RejectReason = "handshake_timeout"
	// RejectNoStartTLS: the client of a STARTTLS listener carried on
	// without asking for TLS (see ErrNoStartTLS).
	RejectNoStartTLS RejectReason = "no_starttls"
	// RejectNegotiationFailed: the STARTTLS negotiation failed some other
	// way, such as the client disconnecting or sending a malformed line.
	RejectNegotiationFailed RejectReason = "negotiation_failed"
	// RejectNoData: the client sent nothing to route on before it
	// disconnected.
	RejectNoData RejectReason = "no_data"
	// RejectNotTLS: the client's first bytes after any negotiation were not
	// a TLS handshake, so an SNI route could not match.
	RejectNotTLS RejectReason = "not_tls"
	// RejectNoSNI: the client's TLS ClientHello named no server.
	RejectNoSNI RejectReason = "no_sni"
	// RejectNoRoute: the client named a host that no route matched.
	RejectNoRoute RejectReason = "no_route"
)

// reject reports reason for a connection that arrived on cfg's listener.
func (p *Proxy) reject(cfg *config, reason RejectReason) {
	if p.OnReject != nil {
		p.OnReject(cfg.ipPort, reason)
	}
}

// isTimeout reports whether err is a deadline being reached.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// negotiationRejectReason classifies a failed STARTTLS negotiation.
func negotiationRejectReason(err error) RejectReason {
	switch {
	case isTimeout(err):
		return RejectHandshakeTimeout
	case errors.Is(err, ErrNoStartTLS):
		return RejectNoStartTLS
	default:
		return RejectNegotiationFailed
	}
}

// recordTypeHandshake is the TLS record type a ClientHello arrives in.
const recordTypeHandshake = 0x16

// routeRejectReason classifies a connection no route matched, from the host
// name route matching found and what the client sent. It must run before
// any HandshakeTimeout deadline is cleared: with nothing buffered it reads
// once more, which then fails at once on the expired deadline or the closed
// connection that ended route matching.
func routeRejectReason(br *bufio.Reader, hostName string) RejectReason {
	if hostName != "" {
		return RejectNoRoute
	}
	first, err := br.Peek(1)
	switch {
	case isTimeout(err):
		return RejectHandshakeTimeout
	case err != nil:
		return RejectNoData
	case first[0] != recordTypeHandshake:
		return RejectNotTLS
	default:
		return RejectNoSNI
	}
}

// commandVerb returns the first word of a client's command line, quoted, for
// error messages. The rest can hold addresses, such as MAIL FROM's, that
// shouldn't end up in logs.
func commandVerb(line string) string {
	verb, _, _ := strings.Cut(line, " ")
	return strconv.Quote(verb)
}
