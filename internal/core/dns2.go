package core

import (
	"github.com/schubergphilis/mercury/internal/config"
)

func (m Manager) dnsServiceStart() {
	m.dnsService.LoadSettings(&config.Get().DNS.Settings)
	m.dnsService.Start()
}

func (m Manager) dnsServiceReload() {
	if m.dnsService.Settings.Addr != config.Get().DNS.Settings.Addr {
		m.dnsService.Stop()
		m.dnsService.LoadSettings(&config.Get().DNS.Settings)
		m.dnsService.Start()
		return
	}
	m.dnsService.LoadSettings(&config.Get().DNS.Settings)
}
