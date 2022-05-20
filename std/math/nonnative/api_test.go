package nonnative

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type EmulatedApiCircuit struct {
	Params *Params

	X1, X2, X3, X4, X5, X6 Element
	Res                    Element
}

func (c *EmulatedApiCircuit) Define(api frontend.API) error {
	if c.Params != nil {
		api = NewAPI(api, c.Params)
	}
	// compute x1^3 + 5*x2 + (x3-x4) / (x5+x6)
	x13 := api.Mul(c.X1, c.X1, c.X1)
	fx2 := api.Mul(5, c.X2)
	nom := api.Sub(c.X3, c.X4)
	denom := api.Add(c.X5, c.X6)
	free := api.Div(nom, denom)
	res := api.Add(x13, fx2, free)
	api.AssertIsEqual(res, c.Res)
	return nil
}

func TestEmulatedApi(t *testing.T) {
	assert := test.NewAssert(t)

	r := ecc.BN254.Info().Fr.Modulus()
	params, err := NewParams(32, r)
	assert.NoError(err)

	circuit := EmulatedApiCircuit{
		Params: params,
		X1:     params.Placeholder(),
		X2:     params.Placeholder(),
		X3:     params.Placeholder(),
		X4:     params.Placeholder(),
		X5:     params.Placeholder(),
		X6:     params.Placeholder(),
		Res:    params.Placeholder(),
	}

	val1, _ := rand.Int(rand.Reader, params.r)
	val2, _ := rand.Int(rand.Reader, params.r)
	val3, _ := rand.Int(rand.Reader, params.r)
	val4, _ := rand.Int(rand.Reader, params.r)
	val5, _ := rand.Int(rand.Reader, params.r)
	val6, _ := rand.Int(rand.Reader, params.r)

	tmp := new(big.Int)
	res := new(big.Int)
	// res = x1^3
	tmp.Exp(val1, big.NewInt(3), params.r)
	res.Set(tmp)
	// res = x1^3 + 5*x2
	tmp.Mul(val2, big.NewInt(5))
	res.Add(res, tmp)
	// tmp = (x3-x4)
	tmp.Sub(val3, val4)
	tmp.Mod(tmp, params.r)
	// tmp2 = (x5+x6)
	tmp2 := new(big.Int)
	tmp2.Add(val5, val6)
	// tmp = (x3-x4)/(x5+x6)
	tmp2.ModInverse(tmp2, params.r)
	tmp.Mul(tmp, tmp2)
	tmp.Mod(tmp, params.r)
	// res = x1^3 + 5*x2 + (x3-x4)/(x5+x6)
	res.Add(res, tmp)
	res.Mod(res, params.r)

	witness := EmulatedApiCircuit{
		Params: params,
		X1:     params.ConstantFromBigOrPanic(val1),
		X2:     params.ConstantFromBigOrPanic(val2),
		X3:     params.ConstantFromBigOrPanic(val3),
		X4:     params.ConstantFromBigOrPanic(val4),
		X5:     params.ConstantFromBigOrPanic(val5),
		X6:     params.ConstantFromBigOrPanic(val6),
		Res:    params.ConstantFromBigOrPanic(res),
	}

	assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve))
}
