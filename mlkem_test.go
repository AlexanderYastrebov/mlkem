package mlkem

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
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

func modPow2d(v *[256]uint, d int) {
	for i := range v {
		v[i] %= (1 << d)
	}
}

func multiply(f, g polynomial) polynomial {
	const n = len(polynomial{})
	var t [n * 2]uintq
	for i := range n {
		for j := range n {
			fg := uintq2(f[i]) * uintq2(g[j]) % q
			t[i+j] = (t[i+j] + uintq(fg)) % q
		}
	}
	for i := range n {
		t[i] = (q + t[i] - t[i+n]) % q
	}
	var h polynomial
	copy(h[:], t[:n])
	return h
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
	t.Run("multiply", func(t *testing.T) {
		f := func(f, g polynomial) bool {
			h1 := multiply(f, g)
			h2 := NTTinv(MultiplyNTTs(NTT(f), NTT(g)))
			return h1 == h2
		}
		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})
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
			d1 := MultiplyNTTs(a, add(b, c))
			d2 := add(MultiplyNTTs(a, b), MultiplyNTTs(a, c))
			return d1 == d2
		}
		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})
	t.Run("right distributivity", func(t *testing.T) {
		f := func(a, b, c polynomial) bool {
			// (b + c) · a = (b · a) + (c · a)
			d1 := MultiplyNTTs(add(b, c), a)
			d2 := add(MultiplyNTTs(b, a), MultiplyNTTs(c, a))
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

func TestByteEncodeDecode(t *testing.T) {
	t.Run("q", func(t *testing.T) {
		f := func(f polynomial) bool {
			return f == ByteDecodeQ(ByteEncodeQ(f))
		}
		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})

	t.Run("d", func(t *testing.T) {
		for i := range 11 {
			d := i + 1
			t.Run(fmt.Sprintf("d=%d", d), func(t *testing.T) {
				f := func(f [256]uint) bool {
					modPow2d(&f, d)
					return f == ByteDecode(ByteEncode(f, d), d)
				}
				if err := quick.Check(f, nil); err != nil {
					t.Error(err)
				}
			})
		}
	})
}

func TestCompressDecompress(t *testing.T) {
	t.Run("decompress-compress", func(t *testing.T) {
		for _, d := range []int{1, 4, 5, 10, 11} {
			t.Run(fmt.Sprintf("d=%d", d), func(t *testing.T) {
				f := func(y [256]uint) bool {
					modPow2d(&y, d)
					return y == Compress(Decompress(y, d), d)
				}
				if err := quick.Check(f, nil); err != nil {
					t.Error(err)
				}
			})
		}
	})

	t.Run("compress-decompress", func(t *testing.T) {
		absDiff := func(a, b uintq) uintq {
			if a > b {
				return a - b
			}
			return b - a
		}
		for _, d := range []int{10, 11} {
			t.Run(fmt.Sprintf("d=%d", d), func(t *testing.T) {
				f := func(f polynomial) bool {
					g := Decompress(Compress(f, d), d)
					for i := range f {
						if absDiff(f[i], g[i]) > 2 {
							return false
						}
					}
					return true
				}
				if err := quick.Check(f, nil); err != nil {
					t.Error(err)
				}
			})
		}
	})
}

func TestKPKE(t *testing.T) {
	for _, p := range []struct {
		name                  string
		k, eta1, eta2, du, dv int
	}{
		{name: "ML-KEM-512", k: 2, eta1: 3, eta2: 2, du: 10, dv: 4},
		{name: "ML-KEM-768", k: 3, eta1: 2, eta2: 2, du: 10, dv: 4},
		{name: "ML-KEM-1024", k: 4, eta1: 2, eta2: 2, du: 11, dv: 5},
	} {
		t.Run(p.name, func(t *testing.T) {
			f := func(d, r, m [32]byte) bool {
				ekPKE, dkPKE := KPKEKeyGen(d[:], p.k, p.eta1)

				c := KPKEEncrypt(ekPKE, m[:], r[:], p.k, p.eta1, p.eta2, p.du, p.dv)

				dm := KPKEDecrypt(dkPKE, c, p.k, p.du, p.dv)

				return bytes.Equal(m[:], dm)
			}
			if err := quick.Check(f, nil); err != nil {
				t.Error(err)
			}
		})
	}
}
