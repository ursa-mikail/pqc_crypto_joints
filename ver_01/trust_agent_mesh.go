package main

import (
	"fmt"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Trust-Agent Mesh
// ─────────────────────────────────────────────────────────────────────────────

// AttestationMode describes how a trust agent validates paths.
type AttestationMode int

const (
	DualPathAttestation AttestationMode = iota // attest legacy AND PQC simultaneously
	PQCOnlyAttestation                         // attest PQC path only
	LegacyOnlyAttestation
)

// TrustAgentMeshConfig holds constructor parameters for the mesh.
type TrustAgentMeshConfig struct {
	KEMJoint  *KEMJoint
	SignJoint *SignJoint
	HashJoint *HashJoint
	Attesters []AttestationMode
}

// TrustAgent represents TA-KEM, TA-Sign, or TA-Hash.
type TrustAgent struct {
	Name     string
	Joint    interface{ Status() JointStatus; ActivatePQC(); DeactivateLegacy() }
	Mode     AttestationMode
	pqcPaths []PQCProvider
}

func (ta *TrustAgent) registerPQC(p PQCProvider) {
	ta.pqcPaths = append(ta.pqcPaths, p)
	ta.Joint.ActivatePQC()
}

// TrustAgentMesh is the central orchestrator for dual-path attestation.
type TrustAgentMesh struct {
	taKEM  *TrustAgent
	taSign *TrustAgent
	taHash *TrustAgent
	cfg    TrustAgentMeshConfig
}

func NewTrustAgentMesh(cfg TrustAgentMeshConfig) *TrustAgentMesh {
	mode := DualPathAttestation
	if len(cfg.Attesters) > 0 {
		mode = cfg.Attesters[0]
	}
	return &TrustAgentMesh{
		cfg: cfg,
		taKEM: &TrustAgent{
			Name:  "TA-KEM",
			Joint: cfg.KEMJoint,
			Mode:  mode,
		},
		taSign: &TrustAgent{
			Name:  "TA-Sign",
			Joint: cfg.SignJoint,
			Mode:  mode,
		},
		taHash: &TrustAgent{
			Name:  "TA-Hash",
			Joint: cfg.HashJoint,
			Mode:  mode,
		},
	}
}

func (m *TrustAgentMesh) PrintStatus() {
	for _, ta := range []*TrustAgent{m.taKEM, m.taSign, m.taHash} {
		s := ta.Joint.Status()
		fmt.Printf("  %-10s  legacy=%-20s  pqc=%-30s  mode=%v\n",
			ta.Name, s.LegacyAlg, s.PQCAlg, ta.Mode)
	}
}

// RegisterPQCPath routes a PQC provider to the correct trust agent.
func (m *TrustAgentMesh) RegisterPQCPath(p PQCProvider) {
	switch p.FIPSStandard() {
	case "FIPS 203":
		m.taKEM.registerPQC(p)
		fmt.Printf("  [mesh] registered %s → TA-KEM\n", p.Name())
	case "FIPS 204", "FIPS 205":
		m.taSign.registerPQC(p)
		fmt.Printf("  [mesh] registered %s → TA-Sign\n", p.Name())
	case "FIPS 202":
		m.taHash.registerPQC(p)
		fmt.Printf("  [mesh] registered %s → TA-Hash\n", p.Name())
	default:
		fmt.Printf("  [mesh] WARNING: unknown standard for %s, routing to TA-Sign\n", p.Name())
		m.taSign.registerPQC(p)
	}
}

// PrintPQCPaths dumps all registered second paths.
func (m *TrustAgentMesh) PrintPQCPaths() {
	agents := []*TrustAgent{m.taKEM, m.taSign, m.taHash}
	for _, ta := range agents {
		for _, p := range ta.pqcPaths {
			fmt.Printf("  %-10s  %-32s  %s  cat=%d  params=%s\n",
				ta.Name, p.Name(), p.FIPSStandard(),
				p.SecurityCategory(), p.ParameterSet())
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Attestation
// ─────────────────────────────────────────────────────────────────────────────

// PathResult records the outcome of attesting a single provider.
type PathResult struct {
	ProviderName string
	Standard     string
	Category     int
	LegacyOK     bool
	PQCPathOK    bool
	Compatible   bool
	Notes        string
	Duration     time.Duration
}

// AttestationReport is the result of a full mesh attestation run.
type AttestationReport struct {
	Timestamp time.Time
	Results   []PathResult
	AllPassed bool
}

func (r *AttestationReport) Print() {
	fmt.Printf("  attestation timestamp: %s\n", r.Timestamp.Format(time.RFC3339))
	fmt.Printf("  %-32s  %-9s  cat  leg   pqc   compat  notes\n", "provider", "standard")
	fmt.Println("  " + repeatStr("─", 90))
	for _, res := range r.Results {
		fmt.Printf("  %-32s  %-9s  %d    %-5v %-5v %-7v %s\n",
			res.ProviderName, res.Standard, res.Category,
			boolMark(res.LegacyOK), boolMark(res.PQCPathOK),
			boolMark(res.Compatible), res.Notes)
	}
	fmt.Println("  " + repeatStr("─", 90))
	fmt.Printf("  AllPassed=%v\n", r.AllPassed)
}

// AttestAll runs dual-path attestation for every registered provider.
func (m *TrustAgentMesh) AttestAll() (*AttestationReport, error) {
	report := &AttestationReport{
		Timestamp: time.Now().UTC(),
		AllPassed: true,
	}

	attestAgent := func(ta *TrustAgent) {
		s := ta.Joint.Status()
		for _, pqc := range ta.pqcPaths {
			start := time.Now()
			res := PathResult{
				ProviderName: pqc.Name(),
				Standard:     pqc.FIPSStandard(),
				Category:     pqc.SecurityCategory(),
				LegacyOK:     s.LegacyActive,
				PQCPathOK:    s.PQCActive,
			}
			// Compatibility check: both paths must be independently operable
			res.Compatible = res.LegacyOK && res.PQCPathOK
			if !res.Compatible {
				res.Notes = "path not yet active"
				report.AllPassed = false
			} else {
				res.Notes = "dual-path OK"
			}
			res.Duration = time.Since(start)
			report.Results = append(report.Results, res)
		}
	}

	attestAgent(m.taKEM)
	attestAgent(m.taSign)
	attestAgent(m.taHash)

	return report, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func boolMark(b bool) string {
	if b {
		return "✓"
	}
	return "✗"
}

func repeatStr(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
