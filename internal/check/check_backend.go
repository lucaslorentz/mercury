package check

import (
	"encoding/json"
	"fmt"

	"github.com/schubergphilis/mercury/internal/config"
	"github.com/schubergphilis/mercury/pkg/healthcheck"
	"github.com/schubergphilis/mercury/pkg/logging"
	"github.com/schubergphilis/mercury/pkg/param"
)

// checkBackendsOnline checks if all backends are online
func checkBackendsOnline(pools map[string]config.LoadbalancePool) (int, error) {
	var faultyTargets []string
	var poolsfound = 0
	var backendsfound = 0
	for poolname, pool := range pools {
		if *param.Get().PoolName != "" && *param.Get().PoolName != poolname {
			continue
		}
		poolsfound++
		for backendname, backend := range pool.Backends {
			if *param.Get().BackendName != "" && *param.Get().BackendName != backendname {
				continue
			}
			backendsfound++
			offline := 0
			online := 0

			for _, node := range backend.Nodes {
				if node.Status == healthcheck.Offline {
					offline++
				} else {
					online++
				}
			}

			// active passive: if offline > 1 && online == 0   - we alert if there is more then 1 offline, or none online
			if offline > 1 && online == 0 && backend.BalanceMode.ActivePassive == YES {
				for _, node := range backend.Nodes {
					if node.Status == healthcheck.Offline {
						faultyTargets = append(faultyTargets, fmt.Sprintf("Offline Node:%s:%d (Backend:%s Pool:%s)", node.IP, node.Port, backendname, poolname))
					}
				}
			}

			// non-acitve-passive nodes offline
			if online < backend.BalanceMode.ServingBackendNodes && backend.BalanceMode.ActivePassive != YES {
				for _, node := range backend.Nodes {
					if node.Status == healthcheck.Offline {
						faultyTargets = append(faultyTargets, fmt.Sprintf("%d/%d Online Node:%s:%d (Backend:%s Pool:%s)", online, backend.BalanceMode.ServingBackendNodes, node.IP, node.Port, backendname, poolname))
					}
				}
			}

			// non-acitve-passive too many nodes online
			if online > backend.BalanceMode.ServingBackendNodes && backend.BalanceMode.ActivePassive != YES {
				for _, node := range backend.Nodes {
					if node.Status == healthcheck.Online {
						faultyTargets = append(faultyTargets, fmt.Sprintf("%d/%d Online Node:%s:%d (Backend:%s Pool:%s)", online, backend.BalanceMode.ServingBackendNodes, node.IP, node.Port, backendname, poolname))
					}
				}
			}

		}
	}
	if faultyTargets != nil {
		return CRITICAL, fmt.Errorf("The following node(s) failed their healthcheck(s): %v", faultyTargets)
	}
	if *param.Get().PoolName != "" && poolsfound == 0 {
		return CRITICAL, fmt.Errorf("No pools found by the name %s", *param.Get().PoolName)
	}
	if *param.Get().BackendName != "" && backendsfound == 0 {
		return CRITICAL, fmt.Errorf("No backends found by the name %s in pool %s", *param.Get().BackendName, *param.Get().PoolName)
	}
	return OK, nil
}

// checkBackendsOnline checks if all backends are online
func checkBackendsHasNodes(pools map[string]config.LoadbalancePool) (int, error) {
	var faultyTargets []string
	for poolname, pool := range pools {
		if *param.Get().PoolName != "" && *param.Get().PoolName != poolname {
			continue
		}
		for backendname, backend := range pool.Backends {
			if *param.Get().BackendName != "" && *param.Get().BackendName != backendname {
				continue
			}
			nodes := 0

			for _, node := range backend.Nodes {
				if node.Status == healthcheck.Online {
					nodes++
				}
			}

			if backend.BalanceMode.ActivePassive == YES {
				if nodes == 0 && len(backend.Nodes) > 1 {
					faultyTargets = append(faultyTargets, fmt.Sprintf("(Backend:%s (Pool:%s)", backendname, poolname))
				}
			} else if backend.ConnectMode != "internal" && nodes == 0 {
				faultyTargets = append(faultyTargets, fmt.Sprintf("(Backend:%s (Pool:%s)", backendname, poolname))
			}
		}
	}

	if faultyTargets != nil {
		return CRITICAL, fmt.Errorf("The following backend(s) have NO nodes available and are Offline: %v", faultyTargets)
	}

	return OK, nil
}

// Backend checks backend status
func Backend() int {
	log := logging.For("check/glb")
	body, err := GetBody(fmt.Sprintf("https://%s:%d/backend", config.Get().Web.Binding, config.Get().Web.Port))

	if err != nil {
		fmt.Printf("Error connecting to Mercury at %s:%d. Is the service running? (error:%s)\n", config.Get().Web.Binding, config.Get().Web.Port, err)
		return CRITICAL
	}

	var loadbalancer config.Loadbalancer
	err = json.Unmarshal(body, &loadbalancer)

	if err != nil {
		fmt.Printf("Error parsing json given by the Mercury service: %s\n", err)
		return CRITICAL
	}

	// Prepare data
	var criticals []string
	var warnings []string

	// Execute Checks
	log.Debug("Checking if backend has atleast 1 node online")
	if exitcode, err := checkBackendsHasNodes(loadbalancer.Pools); err != nil {
		switch exitcode {
		case CRITICAL:
			criticals = append(criticals, err.Error())
		case WARNING:
			warnings = append(warnings, err.Error())
		}
	}

	log.Debug("Checking if all backend nodes are online")
	if exitcode, err := checkBackendsOnline(loadbalancer.Pools); err != nil {
		switch exitcode {
		case CRITICAL:
			criticals = append(criticals, err.Error())
		case WARNING:
			warnings = append(warnings, err.Error())
		}
	}

	if len(criticals) > 0 {
		fmt.Printf("CRITICAL: %+v\n", criticals)
		return CRITICAL
	}

	if len(warnings) > 0 {
		fmt.Printf("WARNING: %v\n", warnings)
		return WARNING
	}

	fmt.Println("OK: All checks are fine!")
	return OK
}
