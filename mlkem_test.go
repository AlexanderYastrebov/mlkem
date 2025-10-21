package mlkem

import (
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

func (polynomial) Generate(*mrand.Rand, int) reflect.Value {
	var f polynomial
	binary.Read(rand.Reader, binary.NativeEndian, &f)
	for i := range f {
		f[i] %= q
	}
	return reflect.ValueOf(f)
}

func testNTTRoundtrip(f polynomial) bool {
	return f == NTTinv(NTT(f))
}

func TestNTT(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		var f polynomial
		if !testNTTRoundtrip(f) {
			t.Error("failed for zero")
		}
	})
	t.Run("quick", func(t *testing.T) {
		if err := quick.Check(testNTTRoundtrip, nil); err != nil {
			t.Fatal(err)
		}
	})
}
