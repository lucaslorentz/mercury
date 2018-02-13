package zdns

import (
	"crypto"
	"encoding/json"
	"net"
	"sync"

	dnssrv "github.com/miekg/dns"
)

// Manager defines the DNS manager type
type Manager struct {
	sync.RWMutex
	addr              string
	allowedForwarding []net.IPNet
	allowedXfer       []net.IPNet
	allowedRequests   []string
	serverTCP         *dnssrv.Server
	serverUDP         *dnssrv.Server
	Log               chan string
	Channels          *ChannelManager
	stop              chan bool
}

// New creates a new DNS manager type
func New(addr string) *Manager {
	m := &Manager{
		addr:              addr,
		allowedForwarding: []net.IPNet{},
		allowedRequests:   []string{"A", "AAAA", "NS", "MX", "SOA", "TXT", "CAA", "ANY", "CNAME", "MB", "MG", "MR", "WKS", "PTR", "HINFO", "MINFO", "SPF"},
		Log:               make(chan string, 500),
		stop:              make(chan bool),
		serverTCP:         &dnssrv.Server{},
		serverUDP:         &dnssrv.Server{},
		Channels:          NewChannelManager(),
	}
	return m
}

// AXFERPassword contains the password for XFERS of the DNS zone
var AXFERPassword = "2093run1Oi23hrqlAhrv3"

// DNSSECKEY contains the public key to sign dns records with
var DNSSECKEY *dnssrv.DNSKEY

// DNSSECPRIV contains the private key to sign dns records with
var DNSSECPRIV crypto.PrivateKey

// Start starts the DNS manager
func (m *Manager) Start() error {
	// start service
	m.log("Starting dns manager")
	dnssrv.Handle(".", m)
	if err := m.initListener(); err != nil {
		return err
	}
	go m.StartChannels()
	return nil
}

// Stop stops the DNS manager
func (m *Manager) Stop() {
	// return if not started
	if m.serverTCP.Addr == "" {
		return
	}
	m.Channels.quit <- true
	m.stopListener()
}

// AllowXfer tests if network is configured to allow AXFERS
func (m *Manager) AllowXfer(ipnet []net.IPNet) {
	m.Lock()
	defer m.Unlock()
	m.allowedXfer = ipnet
}

// AllowForwarding tests if network is configured to allow Forwarding requests
func (m *Manager) AllowForwarding(ipnet []net.IPNet) {
	m.Lock()
	defer m.Unlock()
	m.allowedForwarding = ipnet
}

// AllowRequests configures which dns requests to allow
func (m *Manager) AllowRequests(req []string) {
	m.Lock()
	defer m.Unlock()
	m.allowedRequests = req
}

// Records returns json format of all dns records in dnscache
func (m *Manager) Records() []byte {
	dnscache.Lock()
	defer dnscache.Unlock()
	r, err := json.Marshal(dnscache.Domain)
	if err != nil {
		return []byte("{}")
	}
	return r
}
