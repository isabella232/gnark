package nonnative

import (
	"fmt"
	"math/big"
)

// Recompose takes the limbs in inputs and combines them into res. It errors if
// inputs is uninitialized or zero-length and if the result is uninitialized.
//
// The following holds
//
//    res = \sum_{i=0}^{len(inputs)} inputs[0] * 2^{nbBits * i}
func Recompose(inputs []*big.Int, nbBits uint, res *big.Int) error {
	if len(inputs) == 0 {
		return fmt.Errorf("zero length slice input")
	}
	if res == nil {
		return fmt.Errorf("result not initialized")
	}
	res.SetUint64(0)
	for i := range inputs {
		res.Lsh(res, nbBits)
		res.Add(res, inputs[len(inputs)-i-1])
	}
	return nil
}

// Decompose decomposes the input into res as integers of width nbBits. It
// errors if the decomposition does not fit into res or if res is uninitialized.
//
// The following holds
//
//    input = \sum_{i=0}^{len(res)} res[i] * 2^{nbBits * i}
func Decompose(input *big.Int, nbBits uint, res []*big.Int) error {
	// limb modulus
	if input.BitLen() > len(res)*int(nbBits) {
		return fmt.Errorf("decomposed integer does not fit into res")
	}
	for _, r := range res {
		if r == nil {
			return fmt.Errorf("result slice element uninitalized")
		}
	}
	base := new(big.Int).Lsh(big.NewInt(1), nbBits)
	tmp := new(big.Int).Set(input)
	for i := 0; i < len(res); i++ {
		res[i] = new(big.Int).Mod(tmp, base)
		tmp.Rsh(tmp, nbBits)
	}
	return nil
}

// subPadding returns k*p for some k.
// Denote the padding d=(d[0], ..., d[nbLimbs]). When computing the difference
// of a and b by limb-wise subtraction
//
//     s = a - b = (a[0]-b[0], ..., a[nbLimbs]-b[nbLimbs])
//
// it may happen that some limbs underflow the snark scalar field and the limbs
// of s do not represent the actual difference a-b. However, when adding the
// padding d to every limb i.e.
//
//     s = a + d - b = (a[0]+d[0]-b[0], ..., a[nbLimbs]+d[nbLimbs]-b[nbLimbs])
//
// then no such underflow happens and s = a-b (mod p) as the padding is multiple
// of p.
func subPadding(params *Params, current_overflow uint, nbLimbs uint) []*big.Int {
	// TODO: this method tries to generalize computing the padding both for
	// reduced and unreduced element. maybe separate two methods for clarity?
	padLimbs := make([]*big.Int, nbLimbs)
	for i := 0; i < len(padLimbs); i++ {
		padLimbs[i] = new(big.Int).Lsh(big.NewInt(1), uint(current_overflow)+params.nbBits)
	}
	topBits := 2 * ((uint(params.n.BitLen())-1)%params.nbBits + 1)
	// here is some magic -- if the number of limbs is 2*nbLimbs-1, then we are
	// computing the padding for the unreduced multiplication result. We want to
	// minimize the size of the padding. In addition to only computing the
	// number of bits for the top limb, we also have separate formula for the
	// second largest limb
	top2Bits := ((uint(params.n.BitLen())-1)%params.nbBits + 1) + params.nbBits
	if nbLimbs == 2*params.nbLimbs-1 {
		padLimbs[nbLimbs-1] = new(big.Int).Lsh(big.NewInt(1), topBits)
		padLimbs[nbLimbs-2] = new(big.Int).Lsh(big.NewInt(1), top2Bits)
	}
	pad := new(big.Int)
	if err := Recompose(padLimbs, params.nbBits, pad); err != nil {
		panic(fmt.Sprintf("recompose: %v", err))
	}
	pad.Mod(pad, params.n)
	pad.Sub(params.n, pad)
	ret := make([]*big.Int, nbLimbs)
	for i := range ret {
		ret[i] = new(big.Int)
	}
	if err := Decompose(pad, params.nbBits, ret); err != nil {
		panic(fmt.Sprintf("decompose: %v", err))
	}
	for i := range ret {
		ret[i].Add(ret[i], padLimbs[i])
	}
	return ret
}