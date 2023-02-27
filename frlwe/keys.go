package frlwe

import (
	"fast-ksw/ring"
	"math"
)

type SwitchingKey struct {
	Value [][]*ring.Poly
}

type RelinKey struct {
	Value [2]*SwitchingKey
}

type RotationKey struct {
	Value  [2]*SwitchingKey
	Rotidx uint64
}

func NewSwitchingKey(params Parameters) *SwitchingKey {

	level := params.MaxLevel()
	beta := params.Beta()
	alpha := params.Alpha()
	gamma := params.Gamma()

	blockLen := int(math.Ceil(float64(level+alpha+1) / float64(gamma)))

	swk := new(SwitchingKey)
	swk.Value = make([][]*ring.Poly, beta)

	for i := 0; i < beta; i++ {
		swk.Value[i] = make([]*ring.Poly, blockLen)

		for j := 0; j < blockLen; j++ {
			swk.Value[i][j] = params.RingT().NewPoly()
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

func NewRotationKey(params Parameters, rotidx uint64) *RotationKey {

	rtk := new(RotationKey)
	rtk.Value[0] = NewSwitchingKey(params)
	rtk.Value[1] = NewSwitchingKey(params)
	rtk.Rotidx = rotidx

	return rtk
}
