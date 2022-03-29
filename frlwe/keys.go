package frlwe

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	//"github.com/tuneinsight/lattigo/v3/rlwe"
)

type SwitchingKey struct {
	Value [][]*ring.Poly
}

type RelinearizationKey struct {
	Value [2]*SwitchingKey
}
