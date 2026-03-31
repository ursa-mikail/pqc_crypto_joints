package main

import (
	"fmt"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Prune Gate
//
// The prune gate fires only after every dual-path attestation has passed.
// On success it calls DeactivateLegacy() on all joints, permanently removing
// the legacy paths from the operational mesh.
// ─────────────────────────────────────────────────────────────────────────────

// PrunedPaths records which joints had their legacy path removed.
type PrunedPaths struct {
	KEM  bool
	Sign bool
	Hash bool
	At   time.Time
}

// PruneGate evaluates the attestation report and prunes if safe.
type PruneGate struct {
	mesh   *TrustAgentMesh
	report *AttestationReport
}

func NewPruneGate(mesh *TrustAgentMesh, report *AttestationReport) *PruneGate {
	return &PruneGate{mesh: mesh, report: report}
}

// Evaluate prunes legacy paths if all attestations passed.
func (g *PruneGate) Evaluate() (*PrunedPaths, error) {
	if !g.report.AllPassed {
		return nil, fmt.Errorf("prune gate blocked: not all compatibility checks passed – " +
			"legacy paths retained until dual-path attestation succeeds")
	}

	pruned := &PrunedPaths{At: time.Now().UTC()}

	// Deactivate legacy on every joint
	g.mesh.cfg.KEMJoint.DeactivateLegacy()
	pruned.KEM = true

	g.mesh.cfg.SignJoint.DeactivateLegacy()
	pruned.Sign = true

	g.mesh.cfg.HashJoint.DeactivateLegacy()
	pruned.Hash = true

	return pruned, nil
}

func (g *PruneGate) PrintResult(p *PrunedPaths) {
	if p == nil {
		fmt.Println("  ✗ prune gate: BLOCKED (legacy paths remain active)")
		return
	}
	fmt.Printf("  ✓ prune gate PASSED at %s\n", p.At.Format(time.RFC3339))
	fmt.Printf("    KEM joint legacy pruned  : %v\n", p.KEM)
	fmt.Printf("    Sign joint legacy pruned : %v\n", p.Sign)
	fmt.Printf("    Hash joint legacy pruned : %v\n", p.Hash)
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure PQC Operational State
//
// After the prune gate fires, the system is in pure-PQC mode.
// This struct exposes a clean API over the selected PQC providers.
// ─────────────────────────────────────────────────────────────────────────────

// KEMProvider is the interface exposed from a pure-PQC KEM.
type KEMProvider interface {
	PQCProvider
	Encapsulate(msg []byte) (ciphertext, sharedSecret []byte, err error)
	Decapsulate(ciphertext []byte) (sharedSecret []byte, err error)
}

// SignProvider is the interface exposed from a pure-PQC signer.
type SignProvider interface {
	PQCProvider
	Sign(msg []byte) ([]byte, error)
	Verify(msg, sig []byte) (bool, error)
}

// HashProvider is the interface exposed from a pure-PQC hasher.
type HashProvider interface {
	PQCProvider
	Hash(data []byte) ([]byte, error)
}

// PurePQCState is the operational state after full migration.
type PurePQCState struct {
	KEMProvider  KEMProvider
	SignProvider SignProvider
	SLHProvider  SignProvider
	HashProvider HashProvider

	mesh   *TrustAgentMesh
	pruned *PrunedPaths
}

// NewPurePQCState extracts the active PQC providers from the mesh.
func NewPurePQCState(mesh *TrustAgentMesh, pruned *PrunedPaths) *PurePQCState {
	state := &PurePQCState{mesh: mesh, pruned: pruned}

	// Pull the first registered provider of each type
	for _, p := range mesh.taKEM.pqcPaths {
		if kem, ok := p.(KEMProvider); ok && state.KEMProvider == nil {
			state.KEMProvider = kem
		}
	}
	for _, p := range mesh.taSign.pqcPaths {
		if sp, ok := p.(SignProvider); ok {
			if state.SignProvider == nil {
				state.SignProvider = sp
			} else if state.SLHProvider == nil {
				state.SLHProvider = sp
			}
		}
	}
	for _, p := range mesh.taHash.pqcPaths {
		if hp, ok := p.(HashProvider); ok && state.HashProvider == nil {
			state.HashProvider = hp
		}
	}

	// Fallback: if no hash provider was registered, use SHA3-256
	if state.HashProvider == nil {
		state.HashProvider = NewPQCHashProvider(SHA3_256)
	}
	// Fallback SLH provider
	if state.SLHProvider == nil && state.SignProvider != nil {
		state.SLHProvider = state.SignProvider
	}

	return state
}

// PrintSummary shows the active providers in the pure-PQC state.
func (s *PurePQCState) PrintSummary() {
	fmt.Println("  Active PQC providers (legacy paths PRUNED):")
	if s.KEMProvider != nil {
		fmt.Printf("    KEM  : %-28s  %s  cat=%d\n",
			s.KEMProvider.Name(), s.KEMProvider.FIPSStandard(), s.KEMProvider.SecurityCategory())
	}
	if s.SignProvider != nil {
		fmt.Printf("    Sign : %-28s  %s  cat=%d\n",
			s.SignProvider.Name(), s.SignProvider.FIPSStandard(), s.SignProvider.SecurityCategory())
	}
	if s.SLHProvider != nil && s.SLHProvider != s.SignProvider {
		fmt.Printf("    SLH  : %-28s  %s  cat=%d\n",
			s.SLHProvider.Name(), s.SLHProvider.FIPSStandard(), s.SLHProvider.SecurityCategory())
	}
	if s.HashProvider != nil {
		fmt.Printf("    Hash : %-28s  %s  cat=%d\n",
			s.HashProvider.Name(), s.HashProvider.FIPSStandard(), s.HashProvider.SecurityCategory())
	}
	fmt.Printf("  Pruned at: %s\n", s.pruned.At.Format(time.RFC3339))
	fmt.Println("  All traffic: ML-KEM · ML-DSA · SLH-DSA · SHA-3/SHAKE")
}
