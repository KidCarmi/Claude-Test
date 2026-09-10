package main

import "fmt"

// bandwidth_health.go — PX-7 operator-contract row.
//
// Bandwidth/QoS policies are full-featured CRUD: they validate, persist,
// version, and sync CP→DP like every other policy surface (bandwidth.go,
// controlplane_snapshot.go), and the GUI panel invites an admin to "Set
// per-group bandwidth limits using token bucket rate limiting." What the GUI
// never says is that internal/bandwidth's enforcement primitives
// (Manager.AllowBytes, Manager.FindPolicy) have no caller anywhere on the
// request path — proxy.go, proxy_http.go, proxy_tunnel.go, and socks5.go
// never consult them. A configured policy is fully durable and fully
// invisible to traffic; this is recorded as a known engineering gap
// (roadmap/CHAOS-ENGINEERING-REVIEW.md, PX-7: "Configured QoS silently does
// nothing") but nothing told the ADMIN who configured one. An operator who
// sets a cap, sees it saved, and later finds a node group blew past it has
// no way to learn why short of reading engineering docs or the source.
//
// This closes that blind spot the same way checkSyslogFeed/
// checkCategoryFeedDB do: a side-effect-free read of state the process
// already holds (how many policies are configured), surfaced once as an
// explicit operator-contract row. It changes no enforcement behavior —
// policies still validate, persist, and sync exactly as before.
func checkBandwidthQoSEnforcement() OperatorContractCheck {
	if globalBandwidth == nil {
		return OperatorContractCheck{
			Code:    "bandwidth_qos_enforcement",
			Status:  diagOK,
			Message: "bandwidth/QoS manager not initialized",
		}
	}
	n := len(globalBandwidth.List())
	if n == 0 {
		return OperatorContractCheck{
			Code:    "bandwidth_qos_enforcement",
			Status:  diagOK,
			Message: "no bandwidth/QoS policies configured",
		}
	}
	unit := "policy"
	if n != 1 {
		unit = "policies"
	}
	return OperatorContractCheck{
		Code:   "bandwidth_qos_enforcement",
		Status: diagWarn,
		Message: fmt.Sprintf("%d bandwidth/QoS %s configured but not enforced on the data path — traffic is not currently rate-limited by any of them",
			n, unit),
		OperatorAction: "Configured policies are stored and synced cluster-wide for a future enforcement release; do not rely on them to cap bandwidth today.",
	}
}
