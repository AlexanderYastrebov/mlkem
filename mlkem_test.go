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

func TestMultiplyNTTs(t *testing.T) {
	t.Run("associative", func(t *testing.T) {
		f := func(a, b, c polynomial) bool {
			// (a · b) · c = a · (b · c)
			d1 := MultiplyNTTs(MultiplyNTTs(a, b), c)
			d2 := MultiplyNTTs(a, MultiplyNTTs(b, c))
			return d1 == d2
		}
		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})
	t.Run("left distributivity", func(t *testing.T) {
		f := func(a, b, c polynomial) bool {
			// a · (b + c) = (a · b) + (a · c)
			d1 := MultiplyNTTs(a, Add(b, c))
			d2 := Add(MultiplyNTTs(a, b), MultiplyNTTs(a, c))
			return d1 == d2
		}
		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})
	t.Run("right distributivity", func(t *testing.T) {
		f := func(a, b, c polynomial) bool {
			// (b + c) · a = (b · a) + (c · a)
			d1 := MultiplyNTTs(Add(b, c), a)
			d2 := Add(MultiplyNTTs(b, a), MultiplyNTTs(c, a))
			return d1 == d2
		}
		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})
}

func TestSamplePolyCBD(t *testing.T) {
	testBinominal := func(f polynomial, eta uintq) bool {
		// 0 ≤ 𝑓[𝑖] ≤ 𝜂 or 𝑞 − 𝜂 ≤ 𝑓[𝑖] ≤ 𝑞 − 1
		for i := range f {
			if !((0 <= f[i] && f[i] <= eta) || (q-eta <= f[i] && f[i] <= q-1)) {
				return false
			}
		}
		return true
	}
	t.Run("eta=2", func(t *testing.T) {
		f := func(b [64 * 2]byte) bool {
			f := SamplePolyCBD(b[:])
			return testBinominal(f, 2)
		}
		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})

	t.Run("eta=3", func(t *testing.T) {
		f := func(b [64 * 3]byte) bool {
			f := SamplePolyCBD(b[:])
			return testBinominal(f, 3)
		}
		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})

	t.Run("allocs", func(t *testing.T) {
		b := make([]byte, 64*3)
		rand.Read(b)
		avg := testing.AllocsPerRun(1, func() {
			_ = SamplePolyCBD(b)
		})
		if avg > 0 {
			t.Errorf("Non-zero allocs: %f", avg)
		}
	})
}

func TestSampleNTT(t *testing.T) {
	testPolynomial := func(f polynomial) bool {
		for i := range f {
			if f[i] >= q {
				return false
			}
		}
		return true
	}

	t.Run("quick", func(t *testing.T) {
		f := func(b [34]byte) bool {
			f := SampleNTT(b[:])
			return testPolynomial(f)
		}
		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})

	t.Run("allocs", func(t *testing.T) {
		b := make([]byte, 34)
		rand.Read(b)
		avg := testing.AllocsPerRun(1, func() {
			_ = SampleNTT(b)
		})
		if avg > 0 {
			t.Errorf("Non-zero allocs: %f", avg)
		}
	})
}
