package mlkem

import "crypto/sha3"

const q = 3329

type (
	uintq      uint16
	uintq2     uint32
	polynomial [256]uintq
)

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

func SamplePolyCBD(b []byte) polynomial {
	var f polynomial
	eta := len(b) / 64
	for i := range 256 {
		var x, y int
		for j := range eta {
			x += bit(b, 2*i*eta+j)
			y += bit(b, 2*i*eta+eta+j)
		}
		f[i] = uintq((q + x - y) % q)
	}
	return f
}

func bit(b []byte, i int) int {
	return (int(b[i/8]) >> (i % 8)) & 1
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
