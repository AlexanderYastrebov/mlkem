// Package mlkem implements Module-Lattice-Based Key-Encapsulation Mechanism ([ML-KEM]).
//
// [ML-KEM]: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
package mlkem

import (
	"crypto/rand"
	"errors"

	"github.com/AlexanderYastrebov/mlkem/internal"
)

type ParameterSet struct {
	name                  string
	k, eta1, eta2, du, dv int
}

var (
	MLKEM_512  ParameterSet = ParameterSet{name: "ML-KEM-512", k: 2, eta1: 3, eta2: 2, du: 10, dv: 4}
	MLKEM_768  ParameterSet = ParameterSet{name: "ML-KEM-768", k: 3, eta1: 2, eta2: 2, du: 10, dv: 4}
	MLKEM_1024 ParameterSet = ParameterSet{name: "ML-KEM-1024", k: 4, eta1: 2, eta2: 2, du: 11, dv: 5}
)

type (
	EncapsulationKey []byte
	// Decapsulation key shall remain private.
	DecapsulationKey []byte
	SharedKey        []byte
	Ciphertext       []byte
)

var (
	errInvalidKey        = errors.New("invalid key")
	errInvalidCiphertext = errors.New("invalid ciphertext")
)

// The key generation algorithm accepts no input,
// generates randomness internally, and produces an encapsulation key and a decapsulation key.
// While the encapsulation key can be made public, the decapsulation key shall remain private.
func (p *ParameterSet) KeyGen() (EncapsulationKey, DecapsulationKey) {
	var d, z [32]byte
	rand.Read(d[:])
	rand.Read(z[:])
	ek, dk := internal.KeyGen_internal(d[:], z[:], p.k, p.eta1)
	return ek, dk
}

// KeySeed produces an encapsulation key and a decapsulation key from 64-byte d‖z seed.
func (p *ParameterSet) KeySeed(seed []byte) (EncapsulationKey, DecapsulationKey) {
	if len(seed) != 64 {
		panic("invalid seed")
	}
	d, z := seed[:32], seed[32:]
	ek, dk := internal.KeyGen_internal(d[:], z[:], p.k, p.eta1)
	return ek, dk
}

// The encapsulation algorithm accepts an encapsulation key as input,
// generates randomness internally, and outputs a ciphertext and a shared key.
func (p *ParameterSet) Encaps(ek EncapsulationKey) (SharedKey, Ciphertext, error) {
	if len(ek) != 384*p.k+32 {
		return nil, nil, errInvalidKey
	}
	// TODO: Modulus check
	var m [32]byte
	rand.Read(m[:])
	K, c := internal.Encaps_internal(ek, m[:], p.k, p.eta1, p.eta2, p.du, p.dv)
	return K, c, nil
}

// The decapsulation algorithm accepts a decapsulation key and an ML-KEM ciphertext as input,
// does not use any randomness, and outputs a shared secret.
func (p *ParameterSet) Decaps(dk DecapsulationKey, c Ciphertext) (SharedKey, error) {
	if len(c) != 32*(p.du*p.k+p.dv) {
		return nil, errInvalidCiphertext
	}
	if len(dk) != 768*p.k+96 {
		return nil, errInvalidKey
	}
	// TODO: Hash check
	K := internal.Decaps_internal(dk, c, p.k, p.eta1, p.eta2, p.du, p.dv)
	return K, nil
}

func (p *ParameterSet) String() string {
	return p.name
}
