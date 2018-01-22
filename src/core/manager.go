package core

import (
	"fmt"

	"github.com/schubergphilis/mercury/src/cluster"
	"github.com/schubergphilis/mercury/src/config"
	"github.com/schubergphilis/mercury/src/healthcheck"
	"github.com/schubergphilis/mercury/src/logging"
)

const (
	// YES when yes smimply isn't good enough
	YES = "yes"
)

// Manager main
type Manager struct {
	cluster                         *cluster.Manager
	healthchecks                    chan healthcheck.CheckResult
	dnsdiscard                      chan string
	dnsoffline                      chan string
	dnsupdates                      chan *config.ClusterPacketGlobalDNSUpdate
	clearStatsProxyBackend          chan *config.ClusterPacketClearProxyStatistics
	clusterGlbalDNSStatisticsUpdate chan *config.ClusterPacketGlbalDNSStatisticsUpdate
	addProxyBackend                 chan *config.ProxyBackendNodeUpdate
	removeProxyBackend              chan *config.ProxyBackendNodeUpdate
	proxyBackendStatisticsUpdate    chan *config.ProxyBackendStatisticsUpdate
	/*clusterin                       chan *string
	clusterout                      chan *cluster.Packet
	clusterjoin                     chan *string
	clusterleave                    chan *string*/
	//dnsupdates    chan *config.DNSUpdate
}

// NewManager creates a new manager
func NewManager() *Manager {
	manager := &Manager{
		healthchecks:                    make(chan healthcheck.CheckResult),
		dnsupdates:                      make(chan *config.ClusterPacketGlobalDNSUpdate),
		dnsdiscard:                      make(chan string),
		dnsoffline:                      make(chan string),
		addProxyBackend:                 make(chan *config.ProxyBackendNodeUpdate),
		removeProxyBackend:              make(chan *config.ProxyBackendNodeUpdate),
		proxyBackendStatisticsUpdate:    make(chan *config.ProxyBackendStatisticsUpdate),
		clusterGlbalDNSStatisticsUpdate: make(chan *config.ClusterPacketGlbalDNSStatisticsUpdate),
		clearStatsProxyBackend:          make(chan *config.ClusterPacketClearProxyStatistics),
		/*clusterin:                       make(chan *string),
		clusterout:                      make(chan *cluster.Packet),
		clusterjoin:                     make(chan *string),
		clusterleave:                    make(chan *string),*/
	}
	return manager
}

// Initialize the service
func Initialize(reload <-chan bool) {
	log := logging.For("core/manager/init")
	log.Debug("Initializing Manager")

	manager := NewManager()

	// Create IP's
	CreateListeners()

	// Cluster communication
	go manager.InitializeCluster()

	// HealthCheck's
	healthManager := healthcheck.NewManager()
	go manager.HealthHandler(healthManager)
	go manager.InitializeHealthChecks(healthManager)

	// Create Listeners for Loadbalancer
	if config.Get().Settings.EnableProxy == YES {
		go manager.InitializeProxies()
		go manager.GetAllProxyStatsHandler()
	}

	// DNS updates
	go manager.InitializeDNSUpdates()
	go manager.StartDNSServer()

	// Webserver
	go InitializeWebserver()

	// Statistics
	// Disable stats, we should no longer use this
	/*if config.Get().Stats.Host != "" {
		statsManager := InitializeStats(config.Get().Stats)
		go gatherStats(statsManager)
	}*/

	for {
		select {
		case <-reload:
			log.Info("Reloading Manager")
			// Reload log level
			go logging.Configure(config.Get().Logging.Output, config.Get().Logging.Level)
			// Create new listeners if any
			CreateListeners()
			// Start new DNS Listeners (if changed)
			go manager.StartDNSServer()
			go UpdateDNSConfig()

			// Start new healthchecks, and send exits to no longer used ones
			go manager.InitializeHealthChecks(healthManager)
			// Re-read proxies, and update where needed
			// This needs to be after the healthchecks have been evacuated
			go manager.InitializeProxies()
		}
	}
}

// Cleanup the service
func Cleanup() {
	log := logging.For("core/manager")
	log.Debug("Cleaning up...")
	RemoveListeners()
}

// DumpNodes dumps the current state of all backend nodes
func DumpNodes() {
	for pn, pool := range config.Get().Loadbalancer.Pools {
		for bn, backend := range pool.Backends {
			for nn, node := range backend.Nodes {
				fmt.Printf("MEM DUMP OF CONFIG: pool:%s backend:%s node:%d %+v\n", pn, bn, nn, node)
			}
		}
	}
}