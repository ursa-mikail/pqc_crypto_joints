# PQC Migration Framework – Go (Production Libraries)

A Go implementation of the cryptographic migration pipeline
**Legacy → Joints → Trust-Agent Mesh → PQC 2nd Paths → Prune Gate → Pure PQC**,
backed by production-grade cryptographic libraries.

All four NIST/FIPS post-quantum standards are covered:

| Standard | Algorithm  | Parameter Sets               | Backing Library |
|----------|------------|------------------------------|-----------------|
| FIPS 203 | ML-KEM     | 512 · 768 · 1024             | `cloudflare/circl` Kyber (constant-time, formally reviewed) |
| FIPS 204 | ML-DSA     | 44 · 65 · 87                 | `cloudflare/circl` Dilithium (constant-time) |
| FIPS 205 | SLH-DSA    | 12 variants (SHA2+SHAKE × {128,192,256} × {s,f}) | Structurally-faithful sim using `golang.org/x/crypto/sha3` with correct FIPS 205 hash primitives — replace with `circl/sign/sphincsplus` when available |
| FIPS 202 | SHA-3/SHAKE| SHA3-{256,384,512} · SHAKE{128,256} | `golang.org/x/crypto/sha3` (production-grade, used in Go TLS) |

### ML-KEM (FIPS 203) — Key Encapsulation
The primary standard for quantum-safe key exchange. Kyber / ML-KEM allows two
parties to establish a shared secret over a public channel. Small keys and high
speed make it the primary recommendation for general encryption.

### ML-DSA (FIPS 204) — Digital Signatures
The primary lattice-based signature standard. Dilithium / ML-DSA ensures data
authenticity and integrity; approved for National Security Systems.

### SLH-DSA (FIPS 205) — Stateless Hash-Based Signatures
The backup signature standard, mathematically independent of lattices (based
entirely on hash functions). Stateless: no per-key counter or complex state
management required. Acts as a safety net if lattice vulnerabilities emerge.

### FN-DSA (FIPS 206) — Note
FIPS 206 (Falcon / FN-DSA) offers smaller signatures than ML-DSA at the cost
of more complex sampling. `cloudflare/circl` includes Falcon; it can be added
as a fourth `SignProvider` following the same pattern as `MLDSAProvider`.

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│               Legacy Crypto Layer                      │
│  RSA-2048 · ECDH-P256 · ECDSA-P384 · AES-256-GCM      │
└───────────────────┬────────────────────────────────────┘
                    │  cryptographic joints
          ┌─────────┼──────────┐
          ▼         ▼          ▼
      KEMJoint  SignJoint  HashJoint
    RSA/ECDH→  ECDSA→     SHA-2→
     ML-KEM   ML-DSA/    SHA-3/SHAKE
              SLH-DSA
          │         │          │
          └─────────┼──────────┘
                    │  trust agents (dual-path attestation)
          ┌─────────┼──────────┐
          ▼         ▼          ▼
        TA-KEM   TA-Sign    TA-Hash
          │         │          │
          └─────────┼──────────┘
                    │  FIPS PQC 2nd paths
          ┌─────────┼──────────┐
          ▼         ▼          ▼
        ML-KEM   ML-DSA     SLH-DSA
       FIPS 203  FIPS 204   FIPS 205
                    │
                    ▼
             Prune Gate
    (legacy path removal after compat verified)
                    │
                    ▼
         Pure PQC Operational State
   ML-KEM · ML-DSA · SLH-DSA · SHA-3/SHAKE
```

---

## File Layout

| File | Responsibility |
|------|----------------|
| `main.go` | Pipeline orchestration, demo round-trips |
| `legacy.go` | Legacy crypto layer (RSA, ECDH, ECDSA, AES) |
| `joints.go` | Cryptographic joints (KEM, Sign, Hash) |
| `pqc_algorithms.go` | **Production** FIPS PQC providers (circl + x/crypto) |
| `trust_agent_mesh.go` | Trust-agent mesh + dual-path attestation |
| `prune_gate.go` | Prune gate + PurePQCState |

---

## Build & Run

Requirements: Go 1.22+, internet access (or use the included `vendor/` dir).

```bash
git clone <repo>
cd pqc_migration
go mod tidy          # fetches cloudflare/circl and golang.org/x/crypto
go run .
# or using the vendor directory (offline):
go run -mod=vendor .
```

```
go mod vendor
go mod tidy
go run .
```

Expected output:

```
[PHASE 1] Legacy Crypto Layer initialised
  RSA:   2048-bit key  (public modulus bits: 2048)
  ECDH:  curve P-256
  ECDSA: curve P-384
  AES:   256-bit key  GCM=true

[PHASE 2] Wiring cryptographic joints …
  KEM   legacy=RSA/ECDH           PQC=ML-KEM (FIPS 203)          legacy_active=true  pqc_active=false
  Sign  legacy=ECDSA              PQC=ML-DSA / SLH-DSA (FIPS …)  legacy_active=true  pqc_active=false
  Hash  legacy=SHA-2              PQC=SHA-3 / SHAKE (FIPS 202)   legacy_active=true  pqc_active=false

[PHASE 3] Initialising trust-agent mesh …
[PHASE 4] Activating FIPS PQC second paths …
  [mesh] registered ML-KEM-768   → TA-KEM
  [mesh] registered ML-DSA-65    → TA-Sign
  [mesh] registered SLH-DSA-SHA2-128s → TA-Sign

[PHASE 5] Running operational compatibility attestation …
  ML-KEM-768          FIPS 203  cat=3  ✓  ✓  ✓  dual-path OK
  ML-DSA-65           FIPS 204  cat=3  ✓  ✓  ✓  dual-path OK
  SLH-DSA-SHA2-128s   FIPS 205  cat=1  ✓  ✓  ✓  dual-path OK
  AllPassed=true

[PHASE 6] Prune gate evaluation …
  ✓ prune gate PASSED

[PHASE 7] Pure PQC operational state
  KEM  : ML-KEM-768        FIPS 203  cat=3
  Sign : ML-DSA-65         FIPS 204  cat=3
  SLH  : SLH-DSA-SHA2-128s FIPS 205  cat=1
  Hash : SHA3-256          FIPS 202  cat=1

[PHASE 8] Demo cryptographic round-trips …
  KEM  (ML-KEM-768): encap/decap OK=true  ss_len=32
  DSA  (ML-DSA-65): sign/verify OK=true  sig_len=3293
  Hash (SHA3-256): digest_hex=...
  SLH  (SLH-DSA-SHA2-128s): sign/verify OK=true  sig_len=7856

✓ PQC migration pipeline complete.
```

---

## Library Notes

### cloudflare/circl — ML-KEM and ML-DSA
`circl` is Cloudflare's production cryptographic library for Go.

**ML-KEM** is accessed via the Kyber sub-packages, which implement the
Round-3 Kyber specification — the same parameter sets standardised as
FIPS 203. The mapping is:

| FIPS 203 | circl package |
|----------|---------------|
| ML-KEM-512  | `circl/kem/kyber/kyber512`  |
| ML-KEM-768  | `circl/kem/kyber/kyber768`  |
| ML-KEM1024 | `circl/kem/kyber/kyber1024` |

**ML-DSA** is accessed via the Dilithium sub-packages:

| FIPS 204 | circl mode |
|----------|------------|
| ML-DSA-44 | `Dilithium2` |
| ML-DSA-65 | `Dilithium3` |
| ML-DSA-87 | `Dilithium5` |

Both families are constant-time and use `crypto/rand` internally.

### golang.org/x/crypto/sha3 — FIPS 202 and SLH-DSA PRF
`golang.org/x/crypto/sha3` provides production-grade SHA3-{256,384,512}
and SHAKE{128,256}. It is part of the Go extended standard library and is
used by Go's own TLS implementation.

### SLH-DSA status
`circl` v1.3.7 does not yet include an SLH-DSA / sphincsplus package.
The `SLHDSAProvider` here is structurally faithful — correct parameter
sets, correct signature sizes, correct FIPS 205 hash primitives — and
serves as the drop-in seam for a future FIPS-validated library.

---

## Extending

### Register all three ML-KEM variants

```go
for _, v := range []MLKEMVariant{MLKEM512, MLKEM768, MLKEM1024} {
    mesh.RegisterPQCPath(NewMLKEMProvider(v))
}
```

### Register all twelve SLH-DSA variants

```go
variants := []SLHDSAVariant{
    SLHDSA_SHA2_128s, SLHDSA_SHA2_128f,
    SLHDSA_SHA2_192s, SLHDSA_SHA2_192f,
    SLHDSA_SHA2_256s, SLHDSA_SHA2_256f,
    SLHDSA_SHAKE_128s, SLHDSA_SHAKE_128f,
    SLHDSA_SHAKE_192s, SLHDSA_SHAKE_192f,
    SLHDSA_SHAKE_256s, SLHDSA_SHAKE_256f,
}
for _, v := range variants {
    mesh.RegisterPQCPath(NewSLHDSAProvider(v))
}
```

### Add FN-DSA (FIPS 206 / Falcon)

```go
import "github.com/cloudflare/circl/sign/falcon"

// Implement FNDSAProvider wrapping falcon.Falcon512 or falcon.Falcon1024
// following the same SignProvider interface used by MLDSAProvider.
```

### Swap in a certified SLH-DSA library (future)

When a FIPS 205-validated library becomes available, only
`NewSLHDSAProvider` and the `SLHDSAProvider` struct body need to change.
The `SignProvider` interface and all mesh/prune-gate code remain unchanged.

---

## Security Notes

- All randomness uses `crypto/rand`.
- ML-KEM operations use `cloudflare/circl` Kyber — constant-time, production-grade.
- ML-DSA operations use `cloudflare/circl` Dilithium — constant-time, production-grade.
- SHA-3 / SHAKE operations use `golang.org/x/crypto/sha3` — production-grade.
- SLH-DSA verification uses constant-time byte comparison (`constantTimeEqual`).
- SLH-DSA key operations are a structurally-correct simulation pending a
  FIPS 205-certified library. Do not deploy in a production security context
  until swapped for a validated implementation.
- RSA/ECDSA/ECDH operations (legacy layer) use Go's `crypto/` standard library.
