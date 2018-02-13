package zdns

import (
	"net"

	dnssrv "github.com/miekg/dns"
)

const (
	maxRecusion    = 20
	maxNameservers = 4
)

func dnsForward(msg *dnssrv.Msg, q dnssrv.Question, client net.IP) {

	var dnsDomain string
	var dnsHost string
	switch q.Qtype {
	case dnssrv.TypeSOA, dnssrv.TypeNS, dnssrv.TypeTXT, dnssrv.TypeMX:
		dnsDomain = q.Name
	default:
		dnsHost, dnsDomain = splitDomain(q.Name)
	}

	// Check our existing cache
	err := forwardCache.GetRecursive(msg, 0, dnsDomain, q.Qtype, dnsHost, client, true)
	if err == nil {
		return // we have the record from cache, so exit
	}

	// Get all records, well not really, we just add it to the cache
	_, err = forwardCache.GetRecursiveForward(0, dnsDomain, q.Qtype, dnsHost)
	if err != nil {
		// TODO error handling
		//msg.Rcode = msg.
	}

	// Re-get from cache, it should be there now
	err = forwardCache.GetRecursive(msg, 0, dnsDomain, q.Qtype, dnsHost, client, true)
	if err == nil {
		// TODO error handling
		return // we have the record from cache, so exit
	}
	return
}

// GetRecursiveForward gets all records for a domain we do not serve
func (c *Cache) GetRecursiveForward(level int, dnsDomain string, dnsQuery uint16, dnsHost string) (rs []Record, err error) {
	honorTTL := true
	client := net.IP{}

	//fmt.Printf("level:%d request to resolve host:%s domain:%s query:%s\n", level, dnsHost, dnsDomain, dnssrv.TypeToString[dnsQuery])

	if level > maxRecusion {
		//fmt.Printf("level:%d reached maxRecursion\n", level, dnsHost, dnsDomain, dnsQuery)
		return []Record{}, ErrMaxRecursion
	}

	rs, err = c.Get(dnsDomain, dnssrv.TypeToString[dnsQuery], dnsHost, client, honorTTL)
	if err != nil {
		//fmt.Printf("level:%d request is not cached host:%s domain:%s query:%s\n", level, dnsHost, dnsDomain, dnssrv.TypeToString[dnsQuery])
		// find the NS servers to resolve this records
		var domain string
		if dnsHost == "" {
			_, domain = splitDomain(dnsDomain)
		} else {
			domain = dnsDomain
		}
		//fmt.Printf("level:%d get ns recursive -> %d\n", level, level+1)
		ns, err := c.GetRecursiveForward(level+1, domain, dnssrv.TypeNS, "")
		if err != nil {
			//fmt.Printf("Level: %d Failed to find NS to resolve%v\n", level)
			return nil, err
		}
		//fmt.Printf("Level:%d found ns: %v\n", level, ns)
		/*
			for _, r := range rs {
				fmt.Printf("Level:%d NS record %s returned: %v\n", level, domain, r)
			}*/

		// extract A records from DNS reply:
		var nsA []string
		var nsAAAA []string
		for _, record := range ns {
			if record.Type == "A" { // TODO: ipv6 support for doing remote queries with an ipv6 addr
				//fmt.Printf("FOUND A record in NS: %v\n", record)
				nsA = append(nsA, record.Target)
			}
			if record.Type == "AAAA" {
				nsAAAA = append(nsAAAA, record.Target)
			}
		}
		// if we have ipv4 A records for dns servers, do a lookup
		if len(nsA) == 0 {
			//fmt.Printf("Level: %d Failed to find NS A records to resolve\n", level)
			return nil, ErrNotFound
		}
		rs, err = Resolve(nsA, dnsHost, dnsDomain, dnsQuery)
		if err != nil {
			//fmt.Printf("level:%d resolve failed for host:%s domain:%s query:%d\n", level, dnsHost, dnsDomain, dnsQuery)
			return []Record{}, ErrNotFound
		}

	}

	switch dnsQuery {
	case dnssrv.TypeA, dnssrv.TypeAAAA:
		//fmt.Printf("Level:%d Got A/AAAA\n", level)
		for _, record := range rs {
			if record.Type == "CNAME" {
				//fmt.Printf("Got CNAME, try to get its name... %+v\n", record)
				host, domain := splitDomain(record.Target)
				rsA, err := c.GetRecursiveForward(level+1, domain, dnssrv.TypeA, host)
				//fmt.Printf("Got Recursive CNAME: %v\n", rsA)
				if err != nil {
					//fmt.Printf("level:%d error4 for host:%s domain:%s query:%d\n", level, dnsHost, dnsDomain, dnsQuery)
					return rs, err
				}
				rs = append(rs, rsA...)
			}
		}
	case dnssrv.TypeNS:
		for _, nss := range rs {
			if nss.Type != "NS" {
				continue
			}
			if matchingARecord(rs, "A", nss.Target) || matchingARecord(rs, "AAAA", nss.Target) {
				continue
			}
			host, domain := splitDomain(nss.Target)

			//fmt.Printf("Level:%d Finding A records for matching NS record\n", level)
			// final attempt to get missing NS records from cache
			rsA, err := c.GetRecursiveForward(level+1, domain, dnssrv.TypeA, host)
			if err == nil {
				//fmt.Printf("Level:%d ADD A RECORD for %s %s\n", level, domain, host)
				for _, r := range rsA {
					if r.Name == host && r.Domain == domain {
						//fmt.Printf("Level:%d ADD A RECORD for %s %s %v\n", level, domain, host, r)
						rs = append(rs, r)
					}
				}
			}
		}
	}
	//fmt.Printf("level:%d Final request to resolve host:%s domain:%s query:%s\n", level, dnsHost, dnsDomain, dnssrv.TypeToString[dnsQuery])
	//fmt.Printf("Level:%d Final record returned: %v\n", level, rs)
	/*for _, r := range rs {
		fmt.Printf("Level:%d Final record returned: %v\n", level, r)
	}*/
	return rs, nil
}

func matchingARecord(rs []Record, qtype string, target string) bool {
	for _, r := range rs {
		if r.FQDN() == target && r.Type == qtype {
			return true
		}
	}
	return false
}

func ipAllowed(allowed []net.IPNet, client net.IP) bool {
	for _, cidr := range allowed {
		if cidr.Contains(client) {
			return true
		}
	}
	return false
}
