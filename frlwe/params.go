package frlwe

import (
	"fast-ksw/ring"
	"fast-ksw/rlwe"
	"fast-ksw/utils"
	"math"
)

type ParametersLiteral struct {
	LogN  int
	Q     []uint64
	P     []uint64
	T     []uint64
	LogQ  []int `json:",omitempty"`
	LogP  []int `json:",omitempty"`
	Sigma float64
	H     int
}

type Parameters struct {
	rlwe.Parameters
	ringR *ring.Ring
	ringT *ring.Ring
}

func NewParametersFromLiteral(pl ParametersLiteral) (params Parameters) {
	rlweParams, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{LogN: pl.LogN, Q: pl.Q, P: pl.P, LogQ: pl.LogQ, LogP: pl.LogP, H: pl.H, Sigma: pl.Sigma})

	if err != nil {
		panic("cannot NewParametersFromLiteral: rlweParams cannot be generated")
	}

	N := (1 << pl.LogN)
	ringT, err := ring.NewRing(N, pl.T)
	if err != nil {
		panic("cannot NewParametersFromLiteral: ringT cannot be generated")
	}

	moduliR := make([]uint64, 0)
	moduliR = append(moduliR, pl.P...)
	moduliR = append(moduliR, pl.Q...)

	ringR, err := ring.NewRing(N, moduliR)
	if err != nil {
		panic("cannot NewParametersFromLiteral: ringR cannot be generated")
	}

	params.Parameters = rlweParams
	params.ringT = ringT
	params.ringR = ringR

	return
}

func (p Parameters) RingR() *ring.Ring {
	return p.ringR
}

func (p Parameters) RingT() *ring.Ring {
	return p.ringT
}

func (p Parameters) TiOverflowMargin(level int) int {
	return int(math.Exp2(64) / float64(utils.MaxSliceUint64(p.ringT.Modulus[:level+1])))
}

func (p Parameters) Gamma() int {
	return len(p.ringT.Modulus) - p.Alpha()
}
