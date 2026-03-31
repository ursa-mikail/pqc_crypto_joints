package main

import (
	"fmt"
	"log"
	"os"
	"time"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	fmt.Println(banner)

	// ── 1. Build legacy crypto layer ──────────────────────────────────────────
	legacy := NewLegacyCryptoLayer(LegacyConfig{
		RSAKeyBits:   2048,
		ECDHCurve:    "P-256",
		ECDSACurve:   "P-384",
		AESKeyBits:   256,
		AESLegacyGCM: true,
	})

	fmt.Println("\n[PHASE 1] Legacy Crypto Layer initialised")
	legacy.PrintSummary()

	// ── 2. Wire cryptographic joints ──────────────────────────────────────────
	fmt.Println("\n[PHASE 2] Wiring cryptographic joints …")

	kemJoint := NewKEMJoint(legacy)
	signJoint := NewSignJoint(legacy)
	hashJoint := NewHashJoint(legacy)

	kemJoint.PrintStatus()
	signJoint.PrintStatus()
	hashJoint.PrintStatus()

	// ── 3. Initialise trust-agent mesh ────────────────────────────────────────
	fmt.Println("\n[PHASE 3] Initialising trust-agent mesh …")

	mesh := NewTrustAgentMesh(TrustAgentMeshConfig{
		KEMJoint:  kemJoint,
		SignJoint: signJoint,
		HashJoint: hashJoint,
		Attesters: []AttestationMode{DualPathAttestation},
	})
	mesh.PrintStatus()

	// ── 4. Activate FIPS PQC second paths ────────────────────────────────────
	fmt.Println("\n[PHASE 4] Activating FIPS PQC second paths …")

	mlKEM := NewMLKEMProvider(MLKEM768)       // FIPS 203
	mlDSA := NewMLDSAProvider(MLDSA65)        // FIPS 204
	slhDSA := NewSLHDSAProvider(SLHDSA_SHA2_128s) // FIPS 205

	mesh.RegisterPQCPath(mlKEM)
	mesh.RegisterPQCPath(mlDSA)
	mesh.RegisterPQCPath(slhDSA)

	mesh.PrintPQCPaths()

	// ── 5. Run operational compatibility attestation ──────────────────────────
	fmt.Println("\n[PHASE 5] Running operational compatibility attestation …")

	report, err := mesh.AttestAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "attestation failed: %v\n", err)
		os.Exit(1)
	}
	report.Print()

	// ── 6. Prune gate: remove legacy paths if attested ────────────────────────
	fmt.Println("\n[PHASE 6] Prune gate evaluation …")

	gate := NewPruneGate(mesh, report)
	pruned, err := gate.Evaluate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "prune gate error: %v\n", err)
		os.Exit(1)
	}
	gate.PrintResult(pruned)

	// ── 7. Pure PQC operational state ─────────────────────────────────────────
	fmt.Println("\n[PHASE 7] Pure PQC operational state")

	state := NewPurePQCState(mesh, pruned)
	state.PrintSummary()

	// ── 8. Demo round-trips through the final state ───────────────────────────
	fmt.Println("\n[PHASE 8] Demo cryptographic round-trips …")
	runDemos(state)

	fmt.Println("\n✓ PQC migration pipeline complete.")
}

func runDemos(state *PurePQCState) {
	// KEM encapsulate / decapsulate
	{
		msg := []byte("shared-secret-payload")
		ct, ss, err := state.KEMProvider.Encapsulate(msg)
		if err != nil {
			log.Printf("  KEM encap error: %v", err)
		} else {
			ss2, err := state.KEMProvider.Decapsulate(ct)
			if err != nil {
				log.Printf("  KEM decap error: %v", err)
			} else {
				ok := string(ss) == string(ss2)
				fmt.Printf("  KEM  (%s): encap/decap OK=%v  ss_len=%d\n",
					state.KEMProvider.Name(), ok, len(ss))
			}
		}
	}

	// DSA sign / verify
	{
		msg := []byte("hello post-quantum world")
		sig, err := state.SignProvider.Sign(msg)
		if err != nil {
			log.Printf("  Sign error: %v", err)
		} else {
			ok, err := state.SignProvider.Verify(msg, sig)
			if err != nil {
				log.Printf("  Verify error: %v", err)
			} else {
				fmt.Printf("  DSA  (%s): sign/verify OK=%v  sig_len=%d\n",
					state.SignProvider.Name(), ok, len(sig))
			}
		}
	}

	// Hash digest
	{
		data := []byte("hash-me-post-quantum")
		digest, err := state.HashProvider.Hash(data)
		if err != nil {
			log.Printf("  Hash error: %v", err)
		} else {
			fmt.Printf("  Hash (%s): digest_hex=%x…\n",
				state.HashProvider.Name(), digest[:8])
		}
	}

	// SLH-DSA (stateless hash-based) sign / verify
	{
		msg := []byte("stateless hash-based signature demo")
		sig, err := state.SLHProvider.Sign(msg)
		if err != nil {
			log.Printf("  SLH-DSA sign error: %v", err)
		} else {
			ok, err := state.SLHProvider.Verify(msg, sig)
			if err != nil {
				log.Printf("  SLH-DSA verify error: %v", err)
			} else {
				fmt.Printf("  SLH  (%s): sign/verify OK=%v  sig_len=%d\n",
					state.SLHProvider.Name(), ok, len(sig))
			}
		}
	}

	_ = time.Now() // keep import live
}

const banner = `
╔══════════════════════════════════════════════════════════════════╗
║          PQC Migration Framework  –  FIPS 203 / 204 / 205       ║
║  Legacy → Joints → Trust-Agent Mesh → PQC 2nd Paths → Pure PQC  ║
╚══════════════════════════════════════════════════════════════════╝`
