package fckks

import (
	"fast-ksw/frlwe"
	"github.com/tuneinsight/lattigo/v3/ckks"
	"github.com/tuneinsight/lattigo/v3/ring"
)

type ParametersLiteral struct {
	LogN         int
	Q            []uint64
	P            uint64
	R            []uint64
	LogQ         []int `json:",omitempty"`
	LogP         []int `json:",omitempty"`
	Sigma        float64
	LogSlots     int
	DefaultScale float64
	H            int
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
			P:            []uint64{pl.P},
			LogQ:         pl.LogQ,
			LogP:         pl.LogP,
			H:            pl.H,
			Sigma:        pl.Sigma,
			LogSlots:     pl.LogSlots,
			DefaultScale: pl.DefaultScale,
			RingType:     ring.Standard,
		})

	if err != nil {
		panic("cannot NewParametersFromLiteral: rlweParams cannot be generated")
	}

	frlweParams := frlwe.NewParametersFromLiteral(
		frlwe.ParametersLiteral{
			LogN:  pl.LogN,
			Q:     pl.Q,
			P:     pl.P,
			R:     pl.R,
			LogQ:  pl.LogQ,
			LogP:  pl.LogP,
			H:     pl.H,
			Sigma: pl.Sigma,
		})

	params.Parameters = ckksParams
	params.frlweParams = frlweParams

	return
}

func (p Parameters) RingR() *ring.Ring {
	return p.frlweParams.RingR()
}
