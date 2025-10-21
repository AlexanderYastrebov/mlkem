package mlkem

const q = 3329

type uintq uint16
type polynomial [256]uintq

func NTT(f polynomial) polynomial {
	f_ := f
	return f_
}

func NTTinv(f_ polynomial) polynomial {
	f := f_
	return f
}