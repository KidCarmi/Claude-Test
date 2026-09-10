package main

import (
	"path/filepath"
	"testing"
)

func TestCheckBandwidthQoSEnforcement_NilManager(t *testing.T) {
	origBW := globalBandwidth
	defer func() { globalBandwidth = origBW }()
	globalBandwidth = nil

	c := checkBandwidthQoSEnforcement()
	if c.Code != "bandwidth_qos_enforcement" {
		t.Fatalf("Code = %q, want %q", c.Code, "bandwidth_qos_enforcement")
	}
	if c.Status != diagOK {
		t.Fatalf("Status = %q, want %q when the manager was never initialized", c.Status, diagOK)
	}
}

func TestCheckBandwidthQoSEnforcement_NoPolicies(t *testing.T) {
	origBW := globalBandwidth
	defer func() { globalBandwidth = origBW }()
	globalBandwidth = NewBandwidthManager(filepath.Join(t.TempDir(), "bw.json"))

	c := checkBandwidthQoSEnforcement()
	if c.Status != diagOK {
		t.Fatalf("Status = %q, want %q with no policies configured", c.Status, diagOK)
	}
	if c.OperatorAction != "" {
		t.Fatalf("OperatorAction = %q, want empty on an ok row", c.OperatorAction)
	}
}

func TestCheckBandwidthQoSEnforcement_WarnsWhenPoliciesConfigured(t *testing.T) {
	origBW := globalBandwidth
	defer func() { globalBandwidth = origBW }()
	globalBandwidth = NewBandwidthManager(filepath.Join(t.TempDir(), "bw.json"))
	if _, err := globalBandwidth.Add(BandwidthPolicy{
		Name:           "gold-tier",
		LabelSelector:  map[string]string{"tier": "gold"},
		MaxBytesPerSec: 10 * 1024 * 1024,
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	c := checkBandwidthQoSEnforcement()
	if c.Status != diagWarn {
		t.Fatalf("Status = %q, want %q when a policy is configured but unenforced", c.Status, diagWarn)
	}
	if c.OperatorAction == "" {
		t.Fatal("OperatorAction must be set on a warn row so the GUI can render an actionable hint")
	}
}

// TestCheckBandwidthQoSEnforcement_RegisteredInOperatorContract pins that the
// row actually reaches /api/diagnostics — the whole point of the fix is that
// an admin sees this without knowing to call the check function directly.
func TestCheckBandwidthQoSEnforcement_RegisteredInOperatorContract(t *testing.T) {
	origBW := globalBandwidth
	defer func() { globalBandwidth = origBW }()
	globalBandwidth = NewBandwidthManager(filepath.Join(t.TempDir(), "bw.json"))
	if _, err := globalBandwidth.Add(BandwidthPolicy{Name: "p", MaxBytesPerSec: 1024}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	contract := buildOperatorContract()
	for i := range contract.Checks {
		if contract.Checks[i].Code == "bandwidth_qos_enforcement" {
			if contract.Checks[i].Status != diagWarn {
				t.Fatalf("bandwidth_qos_enforcement status = %q, want %q", contract.Checks[i].Status, diagWarn)
			}
			return
		}
	}
	t.Fatal("bandwidth_qos_enforcement check missing from the operator contract")
}
