package frlwe

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"github.com/tuneinsight/lattigo/v3/utils"
	"math"
)

type ParametersLiteral struct {
	LogN  int
	Q     []uint64
	P     uint64
	R     []uint64
	LogQ  []int `json:",omitempty"`
	LogP  []int `json:",omitempty"`
	Sigma float64
	H     int
}

type Parameters struct {
	rlwe.Parameters
	ringR *ring.Ring
}

func NewParametersFromLiteral(pl ParametersLiteral) (params Parameters) {
	rlweParams, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{LogN: pl.LogN, Q: pl.Q, P: []uint64{pl.P}, LogQ: pl.LogQ, LogP: pl.LogP, H: pl.H, Sigma: pl.Sigma})

	if err != nil {
		panic("cannot NewParametersFromLiteral: rlweParams cannot be generated")
	}

	N := (1 << pl.LogN)
	ringR, err := ring.NewRing(N, pl.R)
	if err != nil {
		panic("cannot NewParametersFromLiteral: ringR cannot be generated")
	}

	params.Parameters = rlweParams
	params.ringR = ringR

	return
}

func (p Parameters) RingR() *ring.Ring {
	return p.ringR
}

func (p *Parameters) RiOverflowMargin(level int) int {
	return int(math.Exp2(64) / float64(utils.MaxSliceUint64(p.ringR.Modulus[:level+1])))
}
