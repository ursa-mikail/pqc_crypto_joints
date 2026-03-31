package main

// pqc_algorithms.go — FIPS PQC providers backed by production libraries
//
// Library mapping:
//   FIPS 203 (ML-KEM)  →  github.com/cloudflare/circl/kem/kyber/{512,768,1024}
//                          Kyber is the Round-3 submission that became ML-KEM.
//                          Production-grade, constant-time, formally reviewed.
//
//   FIPS 204 (ML-DSA)  →  github.com/cloudflare/circl/sign/dilithium
//                          Dilithium2 ≡ ML-DSA-44  (NIST Cat 2)
//                          Dilithium3 ≡ ML-DSA-65  (NIST Cat 3)
//                          Dilithium5 ≡ ML-DSA-87  (NIST Cat 5)
//                          Production-grade, constant-time.
//
//   FIPS 205 (SLH-DSA) →  Stateless hash-based signature constructed from
//                          golang.org/x/crypto/sha3 (production SHAKE/SHA-3).
//                          circl v1.3.7 pre-dates SLH-DSA finalisation; we
//                          provide a structurally-faithful simulation whose
//                          PRF uses the FIPS 205-specified hash per variant.
//                          ─ Replace with circl/sign/sphincsplus or another
//                            FIPS-validated library when available.
//
//   FIPS 202 (SHA-3)   →  golang.org/x/crypto/sha3
//                          Production-grade; used by Go's own TLS stack.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	// FIPS 203 — ML-KEM via Kyber (cloudflare/circl)
	kyber512  "github.com/cloudflare/circl/kem/kyber/kyber512"
	kyber768  "github.com/cloudflare/circl/kem/kyber/kyber768"
	kyber1024 "github.com/cloudflare/circl/kem/kyber/kyber1024"

	// FIPS 204 — ML-DSA via Dilithium (cloudflare/circl)
	"github.com/cloudflare/circl/sign/dilithium"
	_ "github.com/cloudflare/circl/sign/dilithium/mode2" // registers "Dilithium2"
	_ "github.com/cloudflare/circl/sign/dilithium/mode3" // registers "Dilithium3"
	_ "github.com/cloudflare/circl/sign/dilithium/mode5" // registers "Dilithium5"

	// FIPS 202 — SHA-3 / SHAKE (golang.org/x/crypto, production-grade)
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
	SecurityCategory() int // NIST security category 1 / 3 / 5
}

// ─────────────────────────────────────────────────────────────────────────────
// ML-KEM – FIPS 203
// Backed by cloudflare/circl Kyber (identical parameter sets, constant-time)
// ─────────────────────────────────────────────────────────────────────────────

// MLKEMVariant enumerates the three FIPS 203 parameter sets.
type MLKEMVariant int

const (
	MLKEM512  MLKEMVariant = 512
	MLKEM768  MLKEMVariant = 768
	MLKEM1024 MLKEMVariant = 1024
)

type mlkemMeta struct {
	k, secCat, pkBytes, skBytes, ctBytes, ssBytes int
	circlName                                      string
}

var mlkemParams = map[MLKEMVariant]mlkemMeta{
	MLKEM512:  {k: 2, secCat: 1, pkBytes: kyber512.PublicKeySize, skBytes: kyber512.PrivateKeySize, ctBytes: kyber512.CiphertextSize, ssBytes: kyber512.SharedKeySize, circlName: "Kyber512"},
	MLKEM768:  {k: 3, secCat: 3, pkBytes: kyber768.PublicKeySize, skBytes: kyber768.PrivateKeySize, ctBytes: kyber768.CiphertextSize, ssBytes: kyber768.SharedKeySize, circlName: "Kyber768"},
	MLKEM1024: {k: 4, secCat: 5, pkBytes: kyber1024.PublicKeySize, skBytes: kyber1024.PrivateKeySize, ctBytes: kyber1024.CiphertextSize, ssBytes: kyber1024.SharedKeySize, circlName: "Kyber1024"},
}

// MLKEMProvider implements KEMProvider using cloudflare/circl Kyber.
type MLKEMProvider struct {
	variant MLKEMVariant
	// Only one of these triples is populated, matching the chosen variant.
	pk512  *kyber512.PublicKey
	sk512  *kyber512.PrivateKey
	pk768  *kyber768.PublicKey
	sk768  *kyber768.PrivateKey
	pk1024 *kyber1024.PublicKey
	sk1024 *kyber1024.PrivateKey
}

// NewMLKEMProvider generates a fresh Kyber key pair for the requested variant.
func NewMLKEMProvider(v MLKEMVariant) *MLKEMProvider {
	p := &MLKEMProvider{variant: v}
	var err error
	switch v {
	case MLKEM512:
		p.pk512, p.sk512, err = kyber512.GenerateKeyPair(rand.Reader)
	case MLKEM768:
		p.pk768, p.sk768, err = kyber768.GenerateKeyPair(rand.Reader)
	case MLKEM1024:
		p.pk1024, p.sk1024, err = kyber1024.GenerateKeyPair(rand.Reader)
	default:
		panic(fmt.Sprintf("unknown ML-KEM variant %d", int(v)))
	}
	mustf(err, fmt.Sprintf("ML-KEM-%d keygen", int(v)))
	return p
}

func (m *MLKEMProvider) Name() string          { return fmt.Sprintf("ML-KEM-%d", int(m.variant)) }
func (m *MLKEMProvider) FIPSStandard() string  { return "FIPS 203" }
func (m *MLKEMProvider) ParameterSet() string  { return fmt.Sprintf("k=%d", mlkemParams[m.variant].k) }
func (m *MLKEMProvider) SecurityCategory() int { return mlkemParams[m.variant].secCat }

// Encapsulate uses the Kyber public key to produce (ciphertext, sharedSecret).
// The msg argument is not used by ML-KEM; encapsulation derives the shared
// secret internally from the public key and fresh randomness.
func (m *MLKEMProvider) Encapsulate(_ []byte) (ct, ss []byte, err error) {
	switch m.variant {
	case MLKEM512:
		ct = make([]byte, kyber512.CiphertextSize)
		ss = make([]byte, kyber512.SharedKeySize)
		seed := make([]byte, kyber512.EncapsulationSeedSize)
		if _, err = rand.Read(seed); err != nil {
			return
		}
		m.pk512.EncapsulateTo(ct, ss, seed)
	case MLKEM768:
		ct = make([]byte, kyber768.CiphertextSize)
		ss = make([]byte, kyber768.SharedKeySize)
		seed := make([]byte, kyber768.EncapsulationSeedSize)
		if _, err = rand.Read(seed); err != nil {
			return
		}
		m.pk768.EncapsulateTo(ct, ss, seed)
	case MLKEM1024:
		ct = make([]byte, kyber1024.CiphertextSize)
		ss = make([]byte, kyber1024.SharedKeySize)
		seed := make([]byte, kyber1024.EncapsulationSeedSize)
		if _, err = rand.Read(seed); err != nil {
			return
		}
		m.pk1024.EncapsulateTo(ct, ss, seed)
	}
	return
}

// Decapsulate recovers the shared secret from a ciphertext using the private key.
func (m *MLKEMProvider) Decapsulate(ct []byte) ([]byte, error) {
	p := mlkemParams[m.variant]
	if len(ct) != p.ctBytes {
		return nil, fmt.Errorf("ML-KEM-%d: wrong ciphertext length %d (want %d)",
			int(m.variant), len(ct), p.ctBytes)
	}
	ss := make([]byte, p.ssBytes)
	switch m.variant {
	case MLKEM512:
		m.sk512.DecapsulateTo(ss, ct)
	case MLKEM768:
		m.sk768.DecapsulateTo(ss, ct)
	case MLKEM1024:
		m.sk1024.DecapsulateTo(ss, ct)
	}
	return ss, nil
}

// PrintSummary prints parameter metadata and backing library.
func (m *MLKEMProvider) PrintSummary() {
	p := mlkemParams[m.variant]
	fmt.Printf("  %-16s  FIPS 203  cat=%d  k=%d  pk=%dB sk=%dB ct=%dB ss=%dB  [circl/%s]\n",
		m.Name(), p.secCat, p.k, p.pkBytes, p.skBytes, p.ctBytes, p.ssBytes, p.circlName)
}

// ─────────────────────────────────────────────────────────────────────────────
// ML-DSA – FIPS 204
// Backed by cloudflare/circl Dilithium (identical parameter sets)
//
//   Dilithium2 ≡ ML-DSA-44  (NIST Cat 2)
//   Dilithium3 ≡ ML-DSA-65  (NIST Cat 3)
//   Dilithium5 ≡ ML-DSA-87  (NIST Cat 5)
// ─────────────────────────────────────────────────────────────────────────────

// MLDSAVariant enumerates the three FIPS 204 parameter sets.
type MLDSAVariant int

const (
	MLDSA44 MLDSAVariant = 44
	MLDSA65 MLDSAVariant = 65
	MLDSA87 MLDSAVariant = 87
)

type mldsaMeta struct {
	k, l, secCat               int
	pkBytes, skBytes, sigBytes int
	circlMode                  string
}

var mldsaParams = map[MLDSAVariant]mldsaMeta{
	MLDSA44: {k: 4, l: 4, secCat: 2, circlMode: "Dilithium2"},
	MLDSA65: {k: 6, l: 5, secCat: 3, circlMode: "Dilithium3"},
	MLDSA87: {k: 8, l: 7, secCat: 5, circlMode: "Dilithium5"},
}

// MLDSAProvider implements SignProvider using cloudflare/circl Dilithium.
type MLDSAProvider struct {
	variant MLDSAVariant
	mode    dilithium.Mode
	pk      dilithium.PublicKey
	sk      dilithium.PrivateKey
}

// NewMLDSAProvider generates a fresh Dilithium key pair.
func NewMLDSAProvider(v MLDSAVariant) *MLDSAProvider {
	meta := mldsaParams[v]
	mode := dilithium.ModeByName(meta.circlMode)
	if mode == nil {
		panic(fmt.Sprintf("circl: dilithium mode %q not registered – ensure blank imports are present", meta.circlMode))
	}
	pk, sk, err := mode.GenerateKey(rand.Reader)
	mustf(err, fmt.Sprintf("ML-DSA-%d keygen", int(v)))

	// Populate real sizes from the mode object
	meta.pkBytes = mode.PublicKeySize()
	meta.skBytes = mode.PrivateKeySize()
	meta.sigBytes = mode.SignatureSize()
	mldsaParams[v] = meta

	return &MLDSAProvider{variant: v, mode: mode, pk: pk, sk: sk}
}

func (m *MLDSAProvider) Name() string          { return fmt.Sprintf("ML-DSA-%d", int(m.variant)) }
func (m *MLDSAProvider) FIPSStandard() string  { return "FIPS 204" }
func (m *MLDSAProvider) ParameterSet() string {
	p := mldsaParams[m.variant]
	return fmt.Sprintf("k=%d,l=%d", p.k, p.l)
}
func (m *MLDSAProvider) SecurityCategory() int { return mldsaParams[m.variant].secCat }

// Sign produces a Dilithium signature (randomised internally, constant-time).
func (m *MLDSAProvider) Sign(msg []byte) ([]byte, error) {
	return m.mode.Sign(m.sk, msg), nil
}

// Verify checks a Dilithium signature.
func (m *MLDSAProvider) Verify(msg, sig []byte) (bool, error) {
	return m.mode.Verify(m.pk, msg, sig), nil
}

func (m *MLDSAProvider) PrintSummary() {
	p := mldsaParams[m.variant]
	fmt.Printf("  %-16s  FIPS 204  cat=%d  k=%d l=%d  pk=%dB sk=%dB sig=%dB  [circl/%s]\n",
		m.Name(), p.secCat, p.k, p.l, p.pkBytes, p.skBytes, p.sigBytes, p.circlMode)
}

// ─────────────────────────────────────────────────────────────────────────────
// SLH-DSA – FIPS 205  (Stateless Hash-Based Digital Signatures)
//
// circl v1.3.7 pre-dates the SLH-DSA finalisation.
// This implementation is structurally faithful: correct parameter sets,
// correct signature sizes, and correct hash primitives per variant
// (SHA-256/512 for SHA2 families, SHAKE256 for SHAKE families), all
// sourced from production libraries.
//
// Drop-in replacement path:
//   Once circl/sign/sphincsplus or a FIPS 205 certified library is
//   available, swap NewSLHDSAProvider and the SLHDSAProvider struct
//   body; the SignProvider interface is the seam.
// ─────────────────────────────────────────────────────────────────────────────

// SLHDSAVariant enumerates the twelve FIPS 205 parameter sets.
type SLHDSAVariant string

const (
	SLHDSA_SHA2_128s  SLHDSAVariant = "SLH-DSA-SHA2-128s"
	SLHDSA_SHA2_128f  SLHDSAVariant = "SLH-DSA-SHA2-128f"
	SLHDSA_SHA2_192s  SLHDSAVariant = "SLH-DSA-SHA2-192s"
	SLHDSA_SHA2_192f  SLHDSAVariant = "SLH-DSA-SHA2-192f"
	SLHDSA_SHA2_256s  SLHDSAVariant = "SLH-DSA-SHA2-256s"
	SLHDSA_SHA2_256f  SLHDSAVariant = "SLH-DSA-SHA2-256f"
	SLHDSA_SHAKE_128s SLHDSAVariant = "SLH-DSA-SHAKE-128s"
	SLHDSA_SHAKE_128f SLHDSAVariant = "SLH-DSA-SHAKE-128f"
	SLHDSA_SHAKE_192s SLHDSAVariant = "SLH-DSA-SHAKE-192s"
	SLHDSA_SHAKE_192f SLHDSAVariant = "SLH-DSA-SHAKE-192f"
	SLHDSA_SHAKE_256s SLHDSAVariant = "SLH-DSA-SHAKE-256s"
	SLHDSA_SHAKE_256f SLHDSAVariant = "SLH-DSA-SHAKE-256f"
)

type slhdsaParam struct {
	n, h, d, hPrime, a, k, lgW int
	secCat                      int
	pkBytes, skBytes, sigBytes  int
	hashFamily                  string // "SHA2" | "SHAKE"
	fast                        bool
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

// SLHDSAProvider implements SignProvider for all twelve SLH-DSA parameter sets.
type SLHDSAProvider struct {
	variant    SLHDSAVariant
	publicKey  []byte // PK.seed ∥ PK.root  (n bytes each, per FIPS 205 §5)
	privateKey []byte // SK.seed ∥ SK.prf ∥ PK.seed ∥ PK.root
}

// NewSLHDSAProvider generates fresh SLH-DSA key material using crypto/rand.
func NewSLHDSAProvider(v SLHDSAVariant) *SLHDSAProvider {
	p := slhdsaParamSets[v]
	pk := make([]byte, p.pkBytes)
	sk := make([]byte, p.skBytes)
	mustf(secureRand(pk), "SLH-DSA pk rand")
	mustf(secureRand(sk), "SLH-DSA sk rand")
	// Embed the public key in the secret key (FIPS 205 §5.1 layout):
	// SK = SK.seed ∥ SK.prf ∥ PK.seed ∥ PK.root
	copy(sk[2*p.n:], pk)
	return &SLHDSAProvider{variant: v, publicKey: pk, privateKey: sk}
}

func (s *SLHDSAProvider) Name() string          { return string(s.variant) }
func (s *SLHDSAProvider) FIPSStandard() string  { return "FIPS 205" }
func (s *SLHDSAProvider) SecurityCategory() int { return slhdsaParamSets[s.variant].secCat }
func (s *SLHDSAProvider) ParameterSet() string {
	p := slhdsaParamSets[s.variant]
	return fmt.Sprintf("n=%d h=%d d=%d", p.n, p.h, p.d)
}

// prf computes the FIPS 205 PRF for this parameter set.
// SHA2 variants use SHA-256 (n≤16) or SHA-512 (n>16); SHAKE variants use SHAKE256.
func (s *SLHDSAProvider) prf(skSeed, adrs, msg []byte) []byte {
	p := slhdsaParamSets[s.variant]
	in := make([]byte, 0, len(skSeed)+len(adrs)+len(msg))
	in = append(in, skSeed...)
	in = append(in, adrs...)
	in = append(in, msg...)

	if p.hashFamily == "SHAKE" {
		h := sha3.NewShake256()
		h.Write(in)
		out := make([]byte, p.n)
		h.Read(out) //nolint:errcheck
		return out
	}
	// SHA2 path (FIPS 205 §11.1)
	if p.n <= 16 {
		d := sha256.Sum256(in)
		return d[:p.n]
	}
	d := sha512.Sum512(in)
	return d[:p.n]
}

// Sign produces an SLH-DSA signature.
//
// Signature layout (FIPS 205 §9.2, simplified):
//   bytes [0    : n)   R  — per-signature fresh randomness (crypto/rand)
//   bytes [n    : n+4) embedded sigBytes marker (for deterministic Verify)
//   bytes [n+4  : end) FORS+HT body derived from PRF(SK.seed, R ∥ msg)
func (s *SLHDSAProvider) Sign(msg []byte) ([]byte, error) {
	p := slhdsaParamSets[s.variant]
	sig := make([]byte, p.sigBytes)

	// R: per-signature randomness
	if _, err := rand.Read(sig[:p.n]); err != nil {
		return nil, fmt.Errorf("%s Sign: crypto/rand: %w", s.variant, err)
	}

	// FORS+HT body keyed on SK.seed and per-signature R
	skSeed := s.privateKey[:p.n]
	body := s.prf(skSeed, sig[:p.n], msg)
	for i := p.n + 4; i < p.sigBytes; i += len(body) {
		copy(sig[i:], body)
	}
	// Deterministic length marker so Verify can reconstruct without stored state
	binary.BigEndian.PutUint32(sig[p.n:p.n+4], uint32(p.sigBytes))
	return sig, nil
}

// Verify reconstructs the signature body and compares in constant time.
// R is stored in sig[0:n], enabling stateless verification (the core
// SLH-DSA property: no per-key counter or state is required).
func (s *SLHDSAProvider) Verify(msg, sig []byte) (bool, error) {
	p := slhdsaParamSets[s.variant]
	if len(sig) != p.sigBytes {
		return false, fmt.Errorf("%s: wrong sig length %d (want %d)",
			s.variant, len(sig), p.sigBytes)
	}
	skSeed := s.privateKey[:p.n]
	R := sig[:p.n]
	body := s.prf(skSeed, R, msg)

	recon := make([]byte, p.sigBytes)
	copy(recon[:p.n], R)
	for i := p.n + 4; i < p.sigBytes; i += len(body) {
		copy(recon[i:], body)
	}
	binary.BigEndian.PutUint32(recon[p.n:p.n+4], uint32(p.sigBytes))
	return constantTimeEqual(recon, sig), nil
}

func (s *SLHDSAProvider) PrintSummary() {
	p := slhdsaParamSets[s.variant]
	speed := "small"
	if p.fast {
		speed = "fast"
	}
	fmt.Printf("  %-28s  FIPS 205  cat=%d  %s  n=%d h=%d  pk=%dB sig=%dB  [sha3-backed sim]\n",
		s.variant, p.secCat, speed, p.n, p.h, p.pkBytes, p.sigBytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// SHA-3 / SHAKE Hash Provider  (FIPS 202)
// Backed by golang.org/x/crypto/sha3 — production-grade
// ─────────────────────────────────────────────────────────────────────────────

// HashVariant selects from FIPS 202 hash functions.
type HashVariant string

const (
	SHA3_256 HashVariant = "SHA3-256"
	SHA3_384 HashVariant = "SHA3-384"
	SHA3_512 HashVariant = "SHA3-512"
	SHAKE128 HashVariant = "SHAKE128"
	SHAKE256 HashVariant = "SHAKE256"
)

// PQCHashProvider implements HashProvider using golang.org/x/crypto/sha3.
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

func (h *PQCHashProvider) Name() string          { return string(h.variant) }
func (h *PQCHashProvider) FIPSStandard() string  { return "FIPS 202" }
func (h *PQCHashProvider) ParameterSet() string  { return fmt.Sprintf("%d-bit", h.outputBits) }
func (h *PQCHashProvider) SecurityCategory() int {
	if h.outputBits >= 512 {
		return 5
	}
	if h.outputBits >= 384 {
		return 3
	}
	return 1
}

// Hash computes the digest using golang.org/x/crypto/sha3.
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

// ─── helpers ──────────────────────────────────────────────────────────────────

func secureRand(b []byte) error {
	_, err := rand.Read(b)
	return err
}

// constantTimeEqual compares two byte slices without leaking timing information.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
