package fckks

import (
	"fast-ksw/ckks"
	"fast-ksw/frlwe"
	"fast-ksw/ring"
)

type ParametersLiteral struct {
	LogN         int
	Q            []uint64
	P            []uint64
	T            []uint64
	LogQ         []int `json:",omitempty"`
	LogP         []int `json:",omitempty"`
	Sigma        float64
	LogSlots     int
	DefaultScale float64
	H            int
	Gamma        int
}

type Parameters struct {
	ckks.Parameters
	frlweParams frlwe.Parameters
}

func NewParametersFromLiteral(pl ParametersLiteral) (params Parameters) {
	ckksParams, err := ckks.NewParametersFromLiteral(
		ckks.ParametersLiteral{
			LogN:         pl.LogN,
			Q:            pl.Q,
			P:            pl.P,
			LogQ:         pl.LogQ,
			LogP:         pl.LogP,
			H:            pl.H,
			Sigma:        pl.Sigma,
			LogSlots:     pl.LogSlots,
			DefaultScale: pl.DefaultScale,
			RingType:     ring.Standard,
		})

	if err != nil {
		panic("cannot NewParametersFromLiteral: ckksParams cannot be generated")
	}

	frlweParams := frlwe.NewParametersFromLiteral(
		frlwe.ParametersLiteral{
			LogN:  pl.LogN,
			Q:     pl.Q,
			P:     pl.P,
			T:     pl.T,
			LogQ:  pl.LogQ,
			LogP:  pl.LogP,
			H:     pl.H,
			Sigma: pl.Sigma,
			Gamma: pl.Gamma,
		})

	params.Parameters = ckksParams
	params.frlweParams = frlweParams

	return
}

func (p Parameters) RingR() *ring.Ring {
	return p.frlweParams.RingR()
}
