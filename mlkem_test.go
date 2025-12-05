package mlkem_test

import (
	"bytes"
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
