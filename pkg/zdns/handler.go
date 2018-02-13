package zdns

import (
	"fmt"
	"net"
	"strings"
	"time"

	dnssrv "github.com/miekg/dns"
	"github.com/rdoorn/dns"
)

var (
	// ErrNotAuthorized error message if there is no authorized record
	ErrNotAuthorized = fmt.Errorf("Not Authorized")
	// ErrNotFound error message if there is no record found
	ErrNotFound = fmt.Errorf("record does not exist")
	// ErrMaxRecursion error message we reached max recursion
	ErrMaxRecursion = fmt.Errorf("max recursion reached")
)

// ServeDNS handles DNS requests
func (m *Manager) ServeDNS(w dnssrv.ResponseWriter, r *dnssrv.Msg) {
	msg := new(dnssrv.Msg)
	msg.SetReply(r)
	msg.Compress = false

	var bufsize uint16
	var tcp bool
	if o := r.IsEdns0(); o != nil {
		bufsize = o.UDPSize()
	}
	if bufsize < 512 {
		bufsize = 512
	}
	// with TCP we can send 64K
	if tcp = isTCP(w); tcp {
		bufsize = dns.MaxMsgSize - 1
	}
	// go through the message requests
Opscode:
	switch r.Opcode {
	case dnssrv.OpcodeQuery:
		clientIP := getClientIP(w.RemoteAddr().String())
		switch getMessageCache(clientIP, msg) {
		case MsgRateLimitReached:
			return
		case MsgCached:
			break Opscode
		case MsgNotCached:
		}
		for _, q := range msg.Question {
			if !dnssrv.IsFqdn(q.Name) || q.Name == "." {
				msg.SetRcode(r, dnssrv.RcodeNotAuth)
				break Opscode
			}

			if dnscache.IsServedDomain(q.Name) {
				// Request is a domain name based request of a domain that we server: MX/DNS/XFER
				switch q.Qtype {
				case dnssrv.TypeAXFR:
					if ipAllowed(m.allowedXfer, clientIP) {
						ch := make(chan *dnssrv.Envelope)
						tr := new(dnssrv.Transfer)
						go tr.Out(w, r, ch)
						rs, _ := dnscache.GetAll(q.Name, clientIP, false)
						records, _ := dnsRecordToRR(rs)
						records = encapsulateSOA(records)
						ch <- &dnssrv.Envelope{RR: records}
						close(ch)
						w.Hijack()
						return
					}
					msg.Rcode = dnssrv.RcodeRefused
				default:
					dnsServe(msg, "", q.Name, q.Qtype, clientIP, bufsize)
				}

				// Add to message cache
				addMessageCache(clientIP, msg)
			} else if dnscache.IsServedDomain(getDomain(q.Name)) {
				// we serve Any other record
				host, domain := splitDomain(q.Name)
				dnsServe(msg, host, domain, q.Qtype, clientIP, bufsize)
				msg.Authoritative = true

				// Add to message cache
				addMessageCache(clientIP, msg)

			} else if ipAllowed(m.allowedForwarding, clientIP) {
				// we don't serve this record, but can forward
				dnsForward(msg, q, clientIP)
				continue
			} else {
				// denied
				msg.Rcode = dnssrv.RcodeRefused
			}
		}
	}
	// TSIG
	if r.IsTsig() != nil {
		if w.TsigStatus() == nil {
			// *Msg r has an TSIG record and it was validated
			msg.SetTsig("axfr.", dnssrv.HmacMD5, 300, time.Now().Unix())
		} else {
			// *Msg r has an TSIG records and it was not valided
		}
	}
	// write back the result
	Fit(msg, int(bufsize), tcp)
	w.WriteMsg(msg)
}

func getDomain(fqdn string) string {
	d := strings.Split(fqdn, ".")
	return strings.Join(d[1:], ".")
}

func splitDomain(fqdn string) (string, string) {
	d := strings.Split(fqdn, ".")
	host := d[0]
	domain := strings.Join(d[1:], ".")
	if domain == "" {
		domain = "."
	}
	return host, domain
}

// TODO: proper ipv6
func getClientIP(addr string) net.IP {
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		addr = addr[:idx]
		// ugly for ipv6 parsing
		addr = strings.Replace(addr, "[", "", -1)
		addr = strings.Replace(addr, "]", "", -1)
	}
	return net.ParseIP(addr)
}

// isTCP returns true if the client is connecting over TCP.
func isTCP(w dnssrv.ResponseWriter) bool {
	_, ok := w.RemoteAddr().(*net.TCPAddr)
	return ok
}

// Fit will make m fit the size. If a message is larger than size then entire
// additional section is dropped. If it is still to large and the transport
// is udp we return a truncated message.
// If the transport is tcp we are going to drop RR from the answer section
// until it fits. When this is case the returned bool is true.
func Fit(m *dnssrv.Msg, size int, tcp bool) (*dnssrv.Msg, bool) {
	if m.Len() > size {
		// Check for OPT Records at the end and keep those. TODO(miek)
		//m.Extra = nil
		m.Ns = nil
	}
	if m.Len() < size {
		return m, false
	}

	// With TCP setting TC does not mean anything.
	if !tcp {
		m.Truncated = true
		// fall through here, so we at least return a message that can
		// fit the udp buffer.
	}

	// Additional section is gone, binary search until we have length that fits.
	min, max := 0, len(m.Answer)
	original := make([]dnssrv.RR, len(m.Answer))
	copy(original, m.Answer)
	for {
		if min == max {
			break
		}

		mid := (min + max) / 2
		m.Answer = original[:mid]

		if m.Len() < size {
			min++
			continue
		}
		max = mid

	}
	if max > 1 {
		max--
	}
	m.Answer = m.Answer[:max]
	return m, true
}
