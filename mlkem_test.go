package mlkem_test

import (
	"bytes"
	stdmlkem "crypto/mlkem"
	"testing"

	"github.com/AlexanderYastrebov/mlkem"
)

func TestParameterSet(t *testing.T) {
	for _, p := range []mlkem.ParameterSet{
		mlkem.MLKEM_512, mlkem.MLKEM_768, mlkem.MLKEM_1024,
	} {
		t.Run(p.String(), func(t *testing.T) {
			ek, dk := p.KeyGen()

			K1, c, err := p.Encaps(ek)
			if err != nil {
				t.Fatal(err)
			}

			K2, err := p.Decaps(dk, c)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(K1, K2) {
				t.Errorf("%x != %x", K1, K2)
			}
		})
	}
}

func TestCompatibility(t *testing.T) {
	t.Run("KeySeed", func(t *testing.T) {
		dk, err := stdmlkem.GenerateKey768()
		if err != nil {
			t.Fatal(err)
		}
		ek1 := dk.EncapsulationKey().Bytes()

		ek2, _ := mlkem.MLKEM_768.KeySeed(dk.Bytes())

		if !bytes.Equal(ek1, ek2) {
			t.Error("ek1 != ek2")
		}
	})

	t.Run("Encaps", func(t *testing.T) {
		dk, err := stdmlkem.GenerateKey768()
		if err != nil {
			t.Fatal(err)
		}
		ek := dk.EncapsulationKey().Bytes()

		K1, c, err := mlkem.MLKEM_768.Encaps(ek)
		if err != nil {
			t.Fatal(err)
		}

		K2, err := dk.Decapsulate(c)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(K1, K2) {
			t.Error("K1 != K2")
		}
	})

	t.Run("Decaps", func(t *testing.T) {
		dk, err := stdmlkem.GenerateKey768()
		if err != nil {
			t.Fatal(err)
		}
		K1, c := dk.EncapsulationKey().Encapsulate()

		_, dk2 := mlkem.MLKEM_768.KeySeed(dk.Bytes())
		K2, err := mlkem.MLKEM_768.Decaps(dk2, c)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(K1, K2) {
			t.Error("K1 != K2")
		}
	})
}
