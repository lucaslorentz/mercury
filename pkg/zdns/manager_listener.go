package zdns

import (
	"crypto/md5"
	"fmt"
	"io"
	"net"

	dnssrv "github.com/miekg/dns"
)

func (m *Manager) initListener() error {
	// if nothing changed do not start again
	if m.serverTCP.Addr == m.addr {
		return fmt.Errorf("already active on addr: %s", m.addr)
	}

	// addr changed, stop first
	if m.serverTCP.Addr != "" {
		m.stopListener()
	}

	err := m.startListener()
	return err
}

func md5sum(s string) string {
	h := md5.New()
	io.WriteString(h, s)
	return fmt.Sprintf("%x", h.Sum(nil))

}
func (m *Manager) startListener() error {
	m.Lock()
	defer m.Unlock()
	password := md5sum(AXFERPassword)
	m.log("Starting dns listener on %s", m.addr)
	tcpListener, err := net.Listen("tcp", m.addr)
	if err != nil {
		return fmt.Errorf("Failed to start DNS TCP listener: %s", err)
	}
	m.serverTCP = &dnssrv.Server{Addr: m.addr, Net: "TCP", Listener: tcpListener}
	m.serverTCP.TsigSecret = map[string]string{"axfr.": password}

	udpListener, err := net.ListenPacket("udp", m.addr)
	if err != nil {
		return fmt.Errorf("Failed to start DNS UDP listener: %s", err)
	}
	m.serverUDP = &dnssrv.Server{Addr: m.addr, Net: "UDP", PacketConn: udpListener}
	m.serverUDP.TsigSecret = map[string]string{"axfr.": password}

	go m.serverTCP.ActivateAndServe()
	go m.serverUDP.ActivateAndServe()

	return nil
}

func (m *Manager) stopListener() {
	m.log("Stopping dns listener on %s", m.serverTCP.Addr)
	m.serverTCP.Shutdown()
	m.serverUDP.Shutdown()
}
