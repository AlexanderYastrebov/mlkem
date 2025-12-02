package mlkem

import (
	"crypto/sha3"
)

const q = 3329

type (
	uintq      uint16
	uintq2     uint32
	intq2      int32 // can store range [-2*q^2, 2*q^2]
	polynomial [256]uintq
)

func add(a, b polynomial) polynomial {
	var c polynomial
	for i := range a {
		c[i] = (a[i] + b[i]) % q
	}
	return c
}

func sub(a, b polynomial) polynomial {
	var c polynomial
	for i := range a {
		c[i] = (q + a[i] - b[i]) % q
	}
	return c
}

func vectorAdd(a, b []polynomial) []polynomial {
	k := len(a)
	c := make([]polynomial, k)
	for i := range k {
		c[i] = add(a[i], b[i])
	}
	return c
}

func NTT(f polynomial) polynomial {
	f_ := f
	i := 1
	for len := 128; len >= 2; len /= 2 {
		for start := 0; start < 256; start += 2 * len {
			zeta := zetaBitRev7[i]
			i++
			for j := start; j < start+len; j++ {
				t := uintq(zeta * uintq2(f_[j+len]) % q)
				f_[j+len] = (q + f_[j] - t) % q
				f_[j] = (f_[j] + t) % q
			}
		}
	}
	return f_
}

func NTTinv(f_ polynomial) polynomial {
	f := f_
	i := 127
	for len := 2; len <= 128; len *= 2 {
		for start := 0; start < 256; start += 2 * len {
			zeta := zetaBitRev7[i]
			i--
			for j := start; j < start+len; j++ {
				t := f[j]
				f[j] = (t + f[j+len]) % q
				f[j+len] = uintq(zeta * uintq2(q+f[j+len]-t) % q)
			}
		}
	}
	for i := range f {
		f[i] = uintq(uintq2(f[i]) * 3303 % q) // multiply every entry by 3303 == 128^−1 mod q
	}
	return f
}

func vectorNTTinv(f_ []polynomial) []polynomial {
	k := len(f_)
	g := make([]polynomial, k)
	for i := range k {
		g[i] = NTTinv(f_[i])
	}
	return g
}

func MultiplyNTTs(f_, g_ polynomial) polynomial {
	var h_ polynomial
	for i := range 128 {
		h_[2*i], h_[2*i+1] = BaseCaseMultiply(f_[2*i], f_[2*i+1], g_[2*i], g_[2*i+1], zeta2BitRev7[i])
	}
	return h_
}

func BaseCaseMultiply(a0, a1, b0, b1 uintq, g intq2) (uintq, uintq) {
	a0_, a1_, b0_, b1_ := intq2(a0), intq2(a1), intq2(b0), intq2(b1)
	c0_ := a0_*b0_ + ((a1_*b1_)%q)*g
	c1_ := a0_*b1_ + a1_*b0_
	return uintq((c0_ + q*q) % q), uintq(c1_ % q)
}

func SamplePolyCBD(b []byte) polynomial {
	var f polynomial
	eta := len(b) / 64
	for i := range 256 {
		var x, y int
		for j := range eta {
			x += getBit(b, 2*i*eta+j)
			y += getBit(b, 2*i*eta+eta+j)
		}
		f[i] = uintq((q + x - y) % q)
	}
	return f
}

func SampleNTT(b []byte) polynomial {
	var a polynomial
	xof := sha3.NewSHAKE128()
	xof.Write(b)
	var c [3]byte
	j := 0
	for j < 256 {
		xof.Read(c[:])
		d1 := uintq(c[0]) + 256*uintq(c[1]%16)
		d2 := uintq(c[1]/16) + 16*uintq(c[2])
		if d1 < q {
			a[j] = d1
			j++
		}
		if d2 < q && j < 256 {
			a[j] = d2
			j++
		}
	}
	return a
}

// G(𝑑, 𝑘) ∶= SHA3-512(𝑑‖𝑘)
func G(d []byte, k byte) ([]byte, []byte) {
	g := sha3.New512()
	g.Write(d)
	g.Write([]byte{k})
	b := g.Sum(nil)
	return b[:32], b[32:]
}

// H(𝑠) ∶= SHA3-256(𝑠)
func H(s []byte) []byte {
	h := sha3.New256()
	h.Write(s)
	return h.Sum(nil)
}

// PRF𝜂(𝑠, 𝑏) ∶= SHAKE256(𝑠‖𝑏, 8 ⋅ 64 ⋅ 𝜂)
func PRF(s []byte, b byte, eta int) []byte {
	h := sha3.NewSHAKE256()
	h.Write(s)
	h.Write([]byte{b})
	r := make([]byte, 64*eta)
	h.Read(r)
	return r
}

func KPKEKeyGen(d []byte, k, eta1 int) ([]byte, []byte) {
	ro, sigma := G(d, byte(k))

	var roji [32 + 2]byte
	copy(roji[:], ro)
	A_ := make([][]polynomial, k)
	for i := range k {
		A_[i] = make([]polynomial, k)
		for j := range k {
			roji[32], roji[33] = byte(j), byte(i)
			A_[i][j] = SampleNTT(roji[:])
		}
	}

	var N byte
	s_ := make([]polynomial, k)
	for i := range k {
		s_[i] = NTT(SamplePolyCBD(PRF(sigma, N, int(eta1))))
		N++
	}
	e_ := make([]polynomial, k)
	for i := range k {
		e_[i] = NTT(SamplePolyCBD(PRF(sigma, N, int(eta1))))
		N++
	}

	t_ := vectorAdd(matrixMultiplyNTTs(A_, s_), e_)

	ekPKE := make([]byte, 0, int(k)*(32*12)+32)
	for i := range k {
		ekPKE = append(ekPKE, ByteEncodeQ(t_[i])...)
	}
	ekPKE = append(ekPKE, ro...)

	dkPKE := make([]byte, 0, int(k)*32*12)
	for i := range k {
		dkPKE = append(dkPKE, ByteEncodeQ(s_[i])...)
	}
	return ekPKE, dkPKE
}

func matrixMultiplyNTTs(A_ [][]polynomial, s_ []polynomial) []polynomial {
	k := len(A_)
	r_ := make([]polynomial, k)
	for i := range k {
		r_[i] = dotProductNTTs(A_[i], s_)
	}
	return r_
}

func dotProductNTTs(t_ []polynomial, s_ []polynomial) polynomial {
	k := len(t_)
	var r_ polynomial
	for i := range k {
		r_ = add(r_, MultiplyNTTs(t_[i], s_[i]))
	}
	return r_
}

func transpose(a [][]polynomial) [][]polynomial {
	k := len(a)
	r := make([][]polynomial, k)
	for i := range k {
		r[i] = make([]polynomial, k)
	}
	for i := range k {
		for j := range k {
			r[j][i] = a[i][j]
		}
	}
	return r
}

func KeyGen_internal(d, z []byte, k, eta1 int) ([]byte, []byte) {
	ekPKE, dkPKE := KPKEKeyGen(d, k, eta1)
	ek := ekPKE
	dk := make([]byte, 0, len(dkPKE)+len(ek)+32+len(z))
	dk = append(dk, dkPKE...)
	dk = append(dk, ek...)
	dk = append(dk, H(ek)...)
	dk = append(dk, z...)
	return ek, dk
}

func KPKEEncrypt(ekPKE []byte, m, r []byte, k, eta1, eta2, du, dv int) []byte {
	t_ := make([]polynomial, k)
	for i := range k {
		t_[i] = ByteDecodeQ(ekPKE[32*12*i : 32*12*(i+1)])
	}
	ro := ekPKE[384*k : 384*k+32]

	var roji [32 + 2]byte
	copy(roji[:], ro)
	A_ := make([][]polynomial, k)
	for i := range k {
		A_[i] = make([]polynomial, k)
		for j := range k {
			roji[32], roji[33] = byte(j), byte(i)
			A_[i][j] = SampleNTT(roji[:])
		}
	}

	var N byte
	y_ := make([]polynomial, k)
	for i := range k {
		y_[i] = NTT(SamplePolyCBD(PRF(r, N, eta1)))
		N++
	}
	e1 := make([]polynomial, k)
	for i := range k {
		e1[i] = SamplePolyCBD(PRF(r, N, eta2))
		N++
	}
	e2 := SamplePolyCBD(PRF(r, N, eta2))

	u := vectorAdd(vectorNTTinv(matrixMultiplyNTTs(transpose(A_), y_)), e1)
	mu := Decompress(ByteDecode(m, 1), 1)
	v := add(add(NTTinv(dotProductNTTs(t_, y_)), e2), mu)

	c1 := make([]byte, 0, 32*(du*k+dv))
	for i := range k {
		c1 = append(c1, ByteEncode(Compress(u[i], du), du)...)
	}
	c2 := ByteEncode(Compress(v, dv), dv)
	c := append(c1, c2...)

	return c
}

func KPKEDecrypt(dkPKE []byte, c []byte, k, du, dv int) []byte {
	c1 := c[0 : 32*du*k]
	c2 := c[32*du*k : 32*(du*k+dv)]
	u_ := make([]polynomial, k)
	for i := range k {
		u_[i] = NTT(Decompress(ByteDecode(c1[32*du*i:32*du*(i+1)], du), du))
	}
	v := Decompress(ByteDecode(c2, dv), dv)

	s_ := make([]polynomial, k)
	for i := range k {
		s_[i] = ByteDecodeQ(dkPKE[32*12*i : 32*12*(i+1)])
	}
	w := sub(v, NTTinv(dotProductNTTs(s_, u_)))
	m := ByteEncode(Compress(w, 1), 1)

	return m
}

func ByteEncodeQ(f polynomial) []byte {
	b := make([]byte, 384)
	for i, a := range f {
		for j := range 12 {
			setBit(b, i*12+j, int((a>>j)&1))
		}
	}
	return b
}

func ByteDecodeQ(b []byte) polynomial {
	var f polynomial
	for i := range f {
		var a uintq
		for j := range 12 {
			a |= uintq(getBit(b, i*12+j) << j)
		}
		f[i] = a
	}
	return f
}

func ByteEncode(f [256]uint, d int) []byte {
	b := make([]byte, 32*d)
	for i, a := range f {
		for j := range d {
			setBit(b, i*d+j, int((a>>j)&1))
		}
	}
	return b
}

func ByteDecode(b []byte, d int) [256]uint {
	var f [256]uint
	for i := range f {
		var a uint
		for j := range d {
			a |= uint(getBit(b, i*d+j) << j)
		}
		f[i] = a
	}
	return f
}

func Decompress(b [256]uint, d int) polynomial {
	var f polynomial
	pow2d := uintq2(1 << d)
	for i := range f {
		f[i] = uintq((uintq2(b[i])*q + pow2d/2) / pow2d)
	}
	return f
}

func Compress(f polynomial, d int) [256]uint {
	var b [256]uint
	pow2d := uintq2(1 << d)
	for i := range f {
		fi := f[i]
		// TODO: fix hack
		if fi == q-1 {
			fi--
		}
		b[i] = uint(((uintq2(fi)*pow2d + q/2) / q) % pow2d)
	}
	return b
}

func getBit(b []byte, i int) int {
	return (int(b[i/8]) >> (i % 8)) & 1
}

func setBit(b []byte, i int, v int) {
	b[i/8] |= byte((v << (i % 8)))
}

var zetaBitRev7 = [128]uintq2{
	1, 1729, 2580, 3289, 2642, 630, 1897, 848,
	1062, 1919, 193, 797, 2786, 3260, 569, 1746,
	296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
	1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
	289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
	650, 1977, 2513, 632, 2865, 33, 1320, 1915,
	2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
	2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
	17, 2761, 583, 2649, 1637, 723, 2288, 1100,
	1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
	1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
	939, 2308, 2437, 2388, 733, 2337, 268, 641,
	1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
	1063, 319, 2773, 757, 2099, 561, 2466, 2594,
	2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
	1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
}

var zeta2BitRev7 = [128]intq2{
	17, -17, 2761, -2761, 583, -583, 2649, -2649,
	1637, -1637, 723, -723, 2288, -2288, 1100, -1100,
	1409, -1409, 2662, -2662, 3281, -3281, 233, -233,
	756, -756, 2156, -2156, 3015, -3015, 3050, -3050,
	1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789,
	1847, -1847, 952, -952, 1461, -1461, 2687, -2687,
	939, -939, 2308, -2308, 2437, -2437, 2388, -2388,
	733, -733, 2337, -2337, 268, -268, 641, -641,
	1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220,
	375, -375, 2549, -2549, 2090, -2090, 1645, -1645,
	1063, -1063, 319, -319, 2773, -2773, 757, -757,
	2099, -2099, 561, -561, 2466, -2466, 2594, -2594,
	2804, -2804, 1092, -1092, 403, -403, 1026, -1026,
	1143, -1143, 2150, -2150, 2775, -2775, 886, -886,
	1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029,
	2110, -2110, 2935, -2935, 885, -885, 2154, -2154,
}
