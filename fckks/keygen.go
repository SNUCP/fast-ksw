package fckks

import (
	"fast-ksw/frlwe"
)

func NewKeyGenerator(params Parameters) (kgen *frlwe.KeyGenerator) {
	return frlwe.NewKeyGenerator(params.frlweParams)
}
