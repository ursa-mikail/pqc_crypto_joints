package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"
)

// ─────────────────────────────────────────────────────────────────────────────
// Cryptographic Joints
//
// A "joint" is the interface point between a legacy algorithm and its PQC
// replacement.  It exposes BOTH paths so the trust-agent mesh can attest each
// independently, then prune the legacy side.
// ─────────────────────────────────────────────────────────────────────────────

// JointStatus describes the liveness of each side of a joint.
type JointStatus struct {
	Name          string
	LegacyAlg     string
	PQCAlg        string
	LegacyActive  bool
	PQCActive     bool
}

func (s JointStatus) String() string {
	return fmt.Sprintf("  %-10s  legacy=%-20s PQC=%-30s  legacy_active=%-5v  pqc_active=%-5v",
		s.Name, s.LegacyAlg, s.PQCAlg, s.LegacyActive, s.PQCActive)
}

// ─── KEM Joint (RSA/ECDH → ML-KEM) ──────────────────────────────────────────

// KEMJoint bridges RSA/ECDH key-encapsulation to ML-KEM.
type KEMJoint struct {
	legacy *LegacyCryptoLayer
	status JointStatus
}

func NewKEMJoint(l *LegacyCryptoLayer) *KEMJoint {
	return &KEMJoint{
		legacy: l,
		status: JointStatus{
			Name:         "KEM",
			LegacyAlg:    "RSA/ECDH",
			PQCAlg:       "ML-KEM (FIPS 203)",
			LegacyActive: true,
			PQCActive:    false, // activated when PQC path is registered in mesh
		},
	}
}

// LegacyEncapsulate performs ECDH key agreement (simulated shared secret).
func (j *KEMJoint) LegacyEncapsulate(peerPublicBytes []byte) ([]byte, error) {
	// Derive a deterministic shared secret from the peer public bytes using SHA-256
	// (real ECDH requires the peer's ecdh.PublicKey; we simulate the interface here)
	h := sha256.Sum256(append(j.legacy.ECDHPublicKey().Bytes(), peerPublicBytes...))
	return h[:], nil
}

func (j *KEMJoint) PrintStatus() {
	fmt.Println(j.status)
}

func (j *KEMJoint) Status() JointStatus { return j.status }
func (j *KEMJoint) ActivatePQC()        { j.status.PQCActive = true }
func (j *KEMJoint) DeactivateLegacy()   { j.status.LegacyActive = false }

// ─── Sign Joint (ECDSA → ML-DSA / SLH-DSA) ──────────────────────────────────

// SignJoint bridges ECDSA to ML-DSA (lattice) and SLH-DSA (hash-based).
type SignJoint struct {
	legacy *LegacyCryptoLayer
	status JointStatus
}

func NewSignJoint(l *LegacyCryptoLayer) *SignJoint {
	return &SignJoint{
		legacy: l,
		status: JointStatus{
			Name:         "Sign",
			LegacyAlg:    "ECDSA",
			PQCAlg:       "ML-DSA / SLH-DSA (FIPS 204/205)",
			LegacyActive: true,
			PQCActive:    false,
		},
	}
}

// LegacySign produces an ECDSA signature.
func (j *SignJoint) LegacySign(msg []byte) (r, s *big.Int, err error) {
	h := sha512.Sum384(msg)
	r, s, err = ecdsa.Sign(rand.Reader, j.legacy.ecdsaKey, h[:])
	return
}

// LegacyVerify verifies an ECDSA signature.
func (j *SignJoint) LegacyVerify(msg []byte, r, s *big.Int) bool {
	h := sha512.Sum384(msg)
	return ecdsa.Verify(j.legacy.ECDSAPublicKey(), h[:], r, s)
}

func (j *SignJoint) PrintStatus() {
	fmt.Println(j.status)
}

func (j *SignJoint) Status() JointStatus { return j.status }
func (j *SignJoint) ActivatePQC()        { j.status.PQCActive = true }
func (j *SignJoint) DeactivateLegacy()   { j.status.LegacyActive = false }

// ─── Hash Joint (SHA-2 → SHA-3 / SHAKE) ─────────────────────────────────────

// HashJoint bridges SHA-2 to SHA-3 and SHAKE variants.
type HashJoint struct {
	legacy *LegacyCryptoLayer
	status JointStatus
}

func NewHashJoint(l *LegacyCryptoLayer) *HashJoint {
	return &HashJoint{
		legacy: l,
		status: JointStatus{
			Name:         "Hash",
			LegacyAlg:    "SHA-2",
			PQCAlg:       "SHA-3 / SHAKE (FIPS 202)",
			LegacyActive: true,
			PQCActive:    false,
		},
	}
}

// LegacyHash computes SHA-256 (legacy path).
func (j *HashJoint) LegacyHash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func (j *HashJoint) PrintStatus() {
	fmt.Println(j.status)
}

func (j *HashJoint) Status() JointStatus { return j.status }
func (j *HashJoint) ActivatePQC()        { j.status.PQCActive = true }
func (j *HashJoint) DeactivateLegacy()   { j.status.LegacyActive = false }
