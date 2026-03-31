package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// ─────────────────────────────────────────────────────────────────────────────
// Legacy Crypto Layer
// ─────────────────────────────────────────────────────────────────────────────

// LegacyConfig holds algorithm selection for the legacy layer.
type LegacyConfig struct {
	RSAKeyBits   int
	ECDHCurve    string // "P-256" | "P-384" | "P-521"
	ECDSACurve   string
	AESKeyBits   int
	AESLegacyGCM bool
}

// LegacyCryptoLayer holds initialised legacy key material.
type LegacyCryptoLayer struct {
	cfg       LegacyConfig
	rsaKey    *rsa.PrivateKey
	ecdhKey   *ecdh.PrivateKey
	ecdsaKey  *ecdsa.PrivateKey
	aesKey    []byte
	aesBlock  cipher.AEAD
}

// NewLegacyCryptoLayer generates key material for the legacy layer.
func NewLegacyCryptoLayer(cfg LegacyConfig) *LegacyCryptoLayer {
	l := &LegacyCryptoLayer{cfg: cfg}

	var err error

	// RSA
	l.rsaKey, err = rsa.GenerateKey(rand.Reader, cfg.RSAKeyBits)
	mustf(err, "rsa keygen")

	// ECDH
	l.ecdhKey, err = ecdhCurve(cfg.ECDHCurve).GenerateKey(rand.Reader)
	mustf(err, "ecdh keygen")

	// ECDSA
	l.ecdsaKey, err = ecdsa.GenerateKey(ecdsaCurve(cfg.ECDSACurve), rand.Reader)
	mustf(err, "ecdsa keygen")

	// AES
	l.aesKey = make([]byte, cfg.AESKeyBits/8)
	_, err = rand.Read(l.aesKey)
	mustf(err, "aes key gen")

	if cfg.AESLegacyGCM {
		block, e := aes.NewCipher(l.aesKey)
		mustf(e, "aes cipher")
		l.aesBlock, err = cipher.NewGCM(block)
		mustf(err, "aes-gcm")
	}

	return l
}

// PrintSummary dumps a human-readable inventory.
func (l *LegacyCryptoLayer) PrintSummary() {
	fmt.Printf("  RSA:   %d-bit key  (public modulus bits: %d)\n",
		l.cfg.RSAKeyBits, l.rsaKey.N.BitLen())
	fmt.Printf("  ECDH:  curve %s\n", l.cfg.ECDHCurve)
	fmt.Printf("  ECDSA: curve %s\n", l.cfg.ECDSACurve)
	fmt.Printf("  AES:   %d-bit key  GCM=%v\n", l.cfg.AESKeyBits, l.cfg.AESLegacyGCM)
}

// RSAPublicKey returns the RSA public key.
func (l *LegacyCryptoLayer) RSAPublicKey() *rsa.PublicKey { return &l.rsaKey.PublicKey }

// ECDHPublicKey returns the ECDH public key.
func (l *LegacyCryptoLayer) ECDHPublicKey() *ecdh.PublicKey { return l.ecdhKey.PublicKey() }

// ECDSAPublicKey returns the ECDSA public key.
func (l *LegacyCryptoLayer) ECDSAPublicKey() *ecdsa.PublicKey { return &l.ecdsaKey.PublicKey }

// ─── helpers ─────────────────────────────────────────────────────────────────

func ecdhCurve(name string) ecdh.Curve {
	switch name {
	case "P-256":
		return ecdh.P256()
	case "P-384":
		return ecdh.P384()
	case "P-521":
		return ecdh.P521()
	default:
		panic("unknown ECDH curve: " + name)
	}
}

func ecdsaCurve(name string) elliptic.Curve {
	switch name {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		panic("unknown ECDSA curve: " + name)
	}
}

func mustf(err error, context string) {
	if err != nil {
		panic(fmt.Sprintf("%s: %v", context, err))
	}
}
