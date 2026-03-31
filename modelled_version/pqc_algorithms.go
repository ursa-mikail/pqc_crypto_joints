package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// ─────────────────────────────────────────────────────────────────────────────
// PQC Provider interface
// ─────────────────────────────────────────────────────────────────────────────

// PQCProvider is the common interface for all FIPS PQC algorithm families.
type PQCProvider interface {
	Name() string
	FIPSStandard() string
	ParameterSet() string
	SecurityCategory() int // NIST security category 1/3/5
}

// ─────────────────────────────────────────────────────────────────────────────
// ML-KEM – FIPS 203  (Key Encapsulation Mechanism, lattice / Module-LWE)
// ─────────────────────────────────────────────────────────────────────────────

// MLKEMVariant enumerates the three FIPS 203 parameter sets.
type MLKEMVariant int

const (
	MLKEM512  MLKEMVariant = 512  // k=2 → NIST Cat 1  (128-bit PQ security)
	MLKEM768  MLKEMVariant = 768  // k=3 → NIST Cat 3  (192-bit PQ security)
	MLKEM1024 MLKEMVariant = 1024 // k=4 → NIST Cat 5  (256-bit PQ security)
)

// mlkemParams holds the public ML-KEM parameters for each variant.
var mlkemParams = map[MLKEMVariant]struct {
	k, eta1, eta2, du, dv, secCat int
	pkBytes, skBytes, ctBytes, ssBytes int
}{
	MLKEM512:  {k: 2, eta1: 3, eta2: 2, du: 10, dv: 4, secCat: 1, pkBytes: 800, skBytes: 1632, ctBytes: 768, ssBytes: 32},
	MLKEM768:  {k: 3, eta1: 2, eta2: 2, du: 10, dv: 4, secCat: 3, pkBytes: 1184, skBytes: 2400, ctBytes: 1088, ssBytes: 32},
	MLKEM1024: {k: 4, eta1: 2, eta2: 2, du: 11, dv: 5, secCat: 5, pkBytes: 1568, skBytes: 3168, ctBytes: 1568, ssBytes: 32},
}

// MLKEMProvider implements ML-KEM (FIPS 203).
type MLKEMProvider struct {
	variant MLKEMVariant
	// Simulated key material (production would use a vetted library such as
	// cloudflare/circl or filippo.io/mlkem)
	publicKey  []byte
	privateKey []byte
}

func NewMLKEMProvider(v MLKEMVariant) *MLKEMProvider {
	p := mlkemParams[v]
	pk := make([]byte, p.pkBytes)
	sk := make([]byte, p.skBytes)
	rand.Read(pk) //nolint:errcheck
	rand.Read(sk) //nolint:errcheck
	return &MLKEMProvider{variant: v, publicKey: pk, privateKey: sk}
}

func (m *MLKEMProvider) Name() string         { return fmt.Sprintf("ML-KEM-%d", int(m.variant)) }
func (m *MLKEMProvider) FIPSStandard() string { return "FIPS 203" }
func (m *MLKEMProvider) ParameterSet() string { return fmt.Sprintf("k=%d", mlkemParams[m.variant].k) }
func (m *MLKEMProvider) SecurityCategory() int { return mlkemParams[m.variant].secCat }

// Encapsulate produces a ciphertext and shared secret.
// (Production: use ML-KEM.Encaps from a FIPS-validated library.)
func (m *MLKEMProvider) Encapsulate(_ []byte) (ciphertext, sharedSecret []byte, err error) {
	p := mlkemParams[m.variant]
	ct := make([]byte, p.ctBytes)
	rand.Read(ct) //nolint:errcheck

	// Derive a deterministic shared secret via SHA3-256(pk || ct)
	h := sha3.New256()
	h.Write(m.publicKey)
	h.Write(ct)
	ss := h.Sum(nil)[:p.ssBytes]
	return ct, ss, nil
}

// Decapsulate recovers the shared secret from a ciphertext.
func (m *MLKEMProvider) Decapsulate(ciphertext []byte) (sharedSecret []byte, err error) {
	p := mlkemParams[m.variant]
	if len(ciphertext) != p.ctBytes {
		return nil, fmt.Errorf("ML-KEM-%d: wrong ciphertext length %d (expected %d)",
			int(m.variant), len(ciphertext), p.ctBytes)
	}
	h := sha3.New256()
	h.Write(m.publicKey)
	h.Write(ciphertext)
	ss := h.Sum(nil)[:p.ssBytes]
	return ss, nil
}

func (m *MLKEMProvider) PrintSummary() {
	p := mlkemParams[m.variant]
	fmt.Printf("  %-16s  FIPS 203  cat=%d  k=%d  pk=%dB sk=%dB ct=%dB ss=%dB\n",
		m.Name(), p.secCat, p.k, p.pkBytes, p.skBytes, p.ctBytes, p.ssBytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// ML-DSA – FIPS 204  (Digital Signature Algorithm, lattice / Module-LWE+SIS)
// ─────────────────────────────────────────────────────────────────────────────

// MLDSAVariant enumerates the three FIPS 204 parameter sets.
type MLDSAVariant int

const (
	MLDSA44 MLDSAVariant = 44 // NIST Cat 2  (128-bit PQ security)
	MLDSA65 MLDSAVariant = 65 // NIST Cat 3  (192-bit PQ security)
	MLDSA87 MLDSAVariant = 87 // NIST Cat 5  (256-bit PQ security)
)

var mldsaParams = map[MLDSAVariant]struct {
	k, l, secCat int
	pkBytes, skBytes, sigBytes int
}{
	MLDSA44: {k: 4, l: 4, secCat: 2, pkBytes: 1312, skBytes: 2528, sigBytes: 2420},
	MLDSA65: {k: 6, l: 5, secCat: 3, pkBytes: 1952, skBytes: 4000, sigBytes: 3293},
	MLDSA87: {k: 8, l: 7, secCat: 5, pkBytes: 2592, skBytes: 4864, sigBytes: 4595},
}

// MLDSAProvider implements ML-DSA (FIPS 204).
type MLDSAProvider struct {
	variant    MLDSAVariant
	publicKey  []byte
	privateKey []byte
}

func NewMLDSAProvider(v MLDSAVariant) *MLDSAProvider {
	p := mldsaParams[v]
	pk := make([]byte, p.pkBytes)
	sk := make([]byte, p.skBytes)
	rand.Read(pk) //nolint:errcheck
	rand.Read(sk) //nolint:errcheck
	return &MLDSAProvider{variant: v, publicKey: pk, privateKey: sk}
}

func (m *MLDSAProvider) Name() string         { return fmt.Sprintf("ML-DSA-%d", int(m.variant)) }
func (m *MLDSAProvider) FIPSStandard() string { return "FIPS 204" }
func (m *MLDSAProvider) ParameterSet() string {
	p := mldsaParams[m.variant]
	return fmt.Sprintf("k=%d,l=%d", p.k, p.l)
}
func (m *MLDSAProvider) SecurityCategory() int { return mldsaParams[m.variant].secCat }

// Sign produces an ML-DSA signature (simulated: SHA3-512 + key binding).
func (m *MLDSAProvider) Sign(msg []byte) ([]byte, error) {
	p := mldsaParams[m.variant]
	h := sha3.New512()
	h.Write(m.privateKey[:32]) // key binding prefix
	h.Write(msg)
	core := h.Sum(nil)

	sig := make([]byte, p.sigBytes)
	// Fill with deterministic bytes derived from core
	for i := 0; i < p.sigBytes; i += len(core) {
		copy(sig[i:], core)
	}
	return sig[:p.sigBytes], nil
}

// Verify checks an ML-DSA signature.
func (m *MLDSAProvider) Verify(msg, sig []byte) (bool, error) {
	p := mldsaParams[m.variant]
	if len(sig) != p.sigBytes {
		return false, fmt.Errorf("ML-DSA-%d: wrong signature length", int(m.variant))
	}
	expected, _ := m.Sign(msg)
	return string(expected) == string(sig), nil
}

func (m *MLDSAProvider) PrintSummary() {
	p := mldsaParams[m.variant]
	fmt.Printf("  %-16s  FIPS 204  cat=%d  k=%d l=%d  pk=%dB sk=%dB sig=%dB\n",
		m.Name(), p.secCat, p.k, p.l, p.pkBytes, p.skBytes, p.sigBytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// SLH-DSA – FIPS 205  (Stateless Hash-Based Digital Signature)
// ─────────────────────────────────────────────────────────────────────────────

// SLHDSAVariant enumerates the twelve FIPS 205 parameter sets.
type SLHDSAVariant string

const (
	// SHA2 variants
	SLHDSA_SHA2_128s  SLHDSAVariant = "SLH-DSA-SHA2-128s"
	SLHDSA_SHA2_128f  SLHDSAVariant = "SLH-DSA-SHA2-128f"
	SLHDSA_SHA2_192s  SLHDSAVariant = "SLH-DSA-SHA2-192s"
	SLHDSA_SHA2_192f  SLHDSAVariant = "SLH-DSA-SHA2-192f"
	SLHDSA_SHA2_256s  SLHDSAVariant = "SLH-DSA-SHA2-256s"
	SLHDSA_SHA2_256f  SLHDSAVariant = "SLH-DSA-SHA2-256f"
	// SHAKE variants
	SLHDSA_SHAKE_128s SLHDSAVariant = "SLH-DSA-SHAKE-128s"
	SLHDSA_SHAKE_128f SLHDSAVariant = "SLH-DSA-SHAKE-128f"
	SLHDSA_SHAKE_192s SLHDSAVariant = "SLH-DSA-SHAKE-192s"
	SLHDSA_SHAKE_192f SLHDSAVariant = "SLH-DSA-SHAKE-192f"
	SLHDSA_SHAKE_256s SLHDSAVariant = "SLH-DSA-SHAKE-256s"
	SLHDSA_SHAKE_256f SLHDSAVariant = "SLH-DSA-SHAKE-256f"
)

// slhdsaParams enumerates the published FIPS 205 parameter sizes.
// Fields: n, h, d, hPrime, a, k, lg_w, secCat, pkBytes, skBytes, sigBytes
type slhdsaParam struct {
	n, h, d, hPrime, a, k, lgW int
	secCat                      int
	pkBytes, skBytes, sigBytes  int
	hashFamily                  string // "SHA2" or "SHAKE"
	fast                        bool   // true=f (fast/large), false=s (small/slow)
}

var slhdsaParamSets = map[SLHDSAVariant]slhdsaParam{
	SLHDSA_SHA2_128s:  {n: 16, h: 63, d: 7, hPrime: 9, a: 12, k: 14, lgW: 4, secCat: 1, pkBytes: 32, skBytes: 64, sigBytes: 7856, hashFamily: "SHA2", fast: false},
	SLHDSA_SHA2_128f:  {n: 16, h: 66, d: 22, hPrime: 3, a: 6, k: 33, lgW: 4, secCat: 1, pkBytes: 32, skBytes: 64, sigBytes: 17088, hashFamily: "SHA2", fast: true},
	SLHDSA_SHA2_192s:  {n: 24, h: 63, d: 7, hPrime: 9, a: 14, k: 17, lgW: 4, secCat: 3, pkBytes: 48, skBytes: 96, sigBytes: 16224, hashFamily: "SHA2", fast: false},
	SLHDSA_SHA2_192f:  {n: 24, h: 66, d: 22, hPrime: 3, a: 8, k: 33, lgW: 4, secCat: 3, pkBytes: 48, skBytes: 96, sigBytes: 35664, hashFamily: "SHA2", fast: true},
	SLHDSA_SHA2_256s:  {n: 32, h: 64, d: 8, hPrime: 8, a: 14, k: 22, lgW: 4, secCat: 5, pkBytes: 64, skBytes: 128, sigBytes: 29792, hashFamily: "SHA2", fast: false},
	SLHDSA_SHA2_256f:  {n: 32, h: 68, d: 17, hPrime: 4, a: 9, k: 35, lgW: 4, secCat: 5, pkBytes: 64, skBytes: 128, sigBytes: 49856, hashFamily: "SHA2", fast: true},
	SLHDSA_SHAKE_128s: {n: 16, h: 63, d: 7, hPrime: 9, a: 12, k: 14, lgW: 4, secCat: 1, pkBytes: 32, skBytes: 64, sigBytes: 7856, hashFamily: "SHAKE", fast: false},
	SLHDSA_SHAKE_128f: {n: 16, h: 66, d: 22, hPrime: 3, a: 6, k: 33, lgW: 4, secCat: 1, pkBytes: 32, skBytes: 64, sigBytes: 17088, hashFamily: "SHAKE", fast: true},
	SLHDSA_SHAKE_192s: {n: 24, h: 63, d: 7, hPrime: 9, a: 14, k: 17, lgW: 4, secCat: 3, pkBytes: 48, skBytes: 96, sigBytes: 16224, hashFamily: "SHAKE", fast: false},
	SLHDSA_SHAKE_192f: {n: 24, h: 66, d: 22, hPrime: 3, a: 8, k: 33, lgW: 4, secCat: 3, pkBytes: 48, skBytes: 96, sigBytes: 35664, hashFamily: "SHAKE", fast: true},
	SLHDSA_SHAKE_256s: {n: 32, h: 64, d: 8, hPrime: 8, a: 14, k: 22, lgW: 4, secCat: 5, pkBytes: 64, skBytes: 128, sigBytes: 29792, hashFamily: "SHAKE", fast: false},
	SLHDSA_SHAKE_256f: {n: 32, h: 68, d: 17, hPrime: 4, a: 9, k: 35, lgW: 4, secCat: 5, pkBytes: 64, skBytes: 128, sigBytes: 49856, hashFamily: "SHAKE", fast: true},
}

// SLHDSAProvider implements SLH-DSA (FIPS 205).
type SLHDSAProvider struct {
	variant    SLHDSAVariant
	publicKey  []byte
	privateKey []byte
}

func NewSLHDSAProvider(v SLHDSAVariant) *SLHDSAProvider {
	p := slhdsaParamSets[v]
	pk := make([]byte, p.pkBytes)
	sk := make([]byte, p.skBytes)
	rand.Read(pk) //nolint:errcheck
	rand.Read(sk) //nolint:errcheck
	return &SLHDSAProvider{variant: v, publicKey: pk, privateKey: sk}
}

func (s *SLHDSAProvider) Name() string         { return string(s.variant) }
func (s *SLHDSAProvider) FIPSStandard() string { return "FIPS 205" }
func (s *SLHDSAProvider) ParameterSet() string {
	p := slhdsaParamSets[s.variant]
	return fmt.Sprintf("n=%d h=%d d=%d", p.n, p.h, p.d)
}
func (s *SLHDSAProvider) SecurityCategory() int { return slhdsaParamSets[s.variant].secCat }

// hashMsg selects the correct PRF for the parameter set.
func (s *SLHDSAProvider) hashMsg(msg []byte) []byte {
	p := slhdsaParamSets[s.variant]
	if p.hashFamily == "SHAKE" {
		h := sha3.NewShake256()
		h.Write(s.privateKey[:p.n])
		h.Write(msg)
		out := make([]byte, p.n)
		h.Read(out) //nolint:errcheck
		return out
	}
	// SHA2 path
	if p.n <= 16 {
		h := sha256.Sum256(append(s.privateKey[:p.n], msg...))
		return h[:p.n]
	}
	h := sha512.Sum512(append(s.privateKey[:p.n], msg...))
	return h[:p.n]
}

// Sign produces an SLH-DSA signature (simulated FORS+HT structure).
func (s *SLHDSAProvider) Sign(msg []byte) ([]byte, error) {
	p := slhdsaParamSets[s.variant]
	sig := make([]byte, p.sigBytes)

	// R: randomness prefix (n bytes)
	rand.Read(sig[:p.n]) //nolint:errcheck

	// FORS layer binding: hash(R || SK.seed || msg) tiled into sig body
	core := s.hashMsg(append(sig[:p.n], msg...))
	for i := p.n; i < p.sigBytes; i += len(core) {
		copy(sig[i:], core)
	}
	// Embed a deterministic counter to make Verify round-trip cleanly
	binary.BigEndian.PutUint32(sig[p.n:p.n+4], uint32(p.sigBytes))
	return sig, nil
}

// Verify checks an SLH-DSA signature.
func (s *SLHDSAProvider) Verify(msg, sig []byte) (bool, error) {
	p := slhdsaParamSets[s.variant]
	if len(sig) != p.sigBytes {
		return false, fmt.Errorf("%s: wrong sig length %d (expected %d)",
			s.variant, len(sig), p.sigBytes)
	}
	// Re-derive and compare the body (skip first n bytes which are random R)
	core := s.hashMsg(append(sig[:p.n], msg...))
	recon := make([]byte, p.sigBytes)
	copy(recon[:p.n], sig[:p.n])
	for i := p.n; i < p.sigBytes; i += len(core) {
		copy(recon[i:], core)
	}
	binary.BigEndian.PutUint32(recon[p.n:p.n+4], uint32(p.sigBytes))
	return string(recon) == string(sig), nil
}

func (s *SLHDSAProvider) PrintSummary() {
	p := slhdsaParamSets[s.variant]
	speed := "small"
	if p.fast {
		speed = "fast"
	}
	fmt.Printf("  %-28s  FIPS 205  cat=%d  %s  n=%d h=%d  pk=%dB sig=%dB\n",
		s.variant, p.secCat, speed, p.n, p.h, p.pkBytes, p.sigBytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// SHA-3 / SHAKE Hash Provider  (FIPS 202)
// ─────────────────────────────────────────────────────────────────────────────

// HashVariant selects from FIPS 202 hash functions.
type HashVariant string

const (
	SHA3_256   HashVariant = "SHA3-256"
	SHA3_384   HashVariant = "SHA3-384"
	SHA3_512   HashVariant = "SHA3-512"
	SHAKE128   HashVariant = "SHAKE128"
	SHAKE256   HashVariant = "SHAKE256"
)

// PQCHashProvider implements FIPS 202 hash functions.
type PQCHashProvider struct {
	variant    HashVariant
	outputBits int
}

func NewPQCHashProvider(v HashVariant) *PQCHashProvider {
	bits := map[HashVariant]int{
		SHA3_256: 256, SHA3_384: 384, SHA3_512: 512,
		SHAKE128: 256, SHAKE256: 512,
	}
	return &PQCHashProvider{variant: v, outputBits: bits[v]}
}

func (h *PQCHashProvider) Name() string         { return string(h.variant) }
func (h *PQCHashProvider) FIPSStandard() string { return "FIPS 202" }
func (h *PQCHashProvider) ParameterSet() string { return fmt.Sprintf("%d-bit", h.outputBits) }
func (h *PQCHashProvider) SecurityCategory() int {
	if h.outputBits >= 512 {
		return 5
	}
	if h.outputBits >= 384 {
		return 3
	}
	return 1
}

// Hash computes the digest.
func (h *PQCHashProvider) Hash(data []byte) ([]byte, error) {
	switch h.variant {
	case SHA3_256:
		d := sha3.Sum256(data)
		return d[:], nil
	case SHA3_384:
		d := sha3.Sum384(data)
		return d[:], nil
	case SHA3_512:
		d := sha3.Sum512(data)
		return d[:], nil
	case SHAKE128:
		out := make([]byte, 32)
		sha3.ShakeSum128(out, data)
		return out, nil
	case SHAKE256:
		out := make([]byte, 64)
		sha3.ShakeSum256(out, data)
		return out, nil
	}
	return nil, fmt.Errorf("unknown hash variant: %s", h.variant)
}
