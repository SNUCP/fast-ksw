package frlwe

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	"math"
)

type SwitchingKey struct {
	Value [][]*ring.Poly
}

type RelinKey struct {
	Value [2]*SwitchingKey
}

func NewSwitchingKey(params Parameters) *SwitchingKey {

	gadgetDim := params.Beta()
	decompDim := int(math.Ceil(float64(params.Alpha()+params.Beta()) / float64(params.Gamma())))

	swk := new(SwitchingKey)
	swk.Value = make([][]*ring.Poly, gadgetDim)

	for i := 0; i < gadgetDim; i++ {
		swk.Value[i] = make([]*ring.Poly, decompDim)

		for j := 0; j < decompDim; j++ {
			swk.Value[i][j] = params.RingR().NewPoly()
		}
	}

	return swk
}

func NewRelinKey(params Parameters) *RelinKey {

	rlk := new(RelinKey)
	rlk.Value[0] = NewSwitchingKey(params)
	rlk.Value[1] = NewSwitchingKey(params)

	return rlk
}
