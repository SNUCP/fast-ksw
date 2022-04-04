package fckks

import (
	"testing"
)

func BenchmarkFCKKS(b *testing.B) {
	params := NewParametersFromLiteral(PN15QP880)
	testctx, err := genTestParams(params)
	if err != nil {
		panic(err)
	}

	benchMulNew(testctx, b)
	benchMulOld(testctx, b)
}

func benchMulNew(testctx *testContext, b *testing.B) {
	eval := testctx.eval
	rlk := testctx.rlk

	_, ct0 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))
	_, ct1 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))

	b.Run("MulNew", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.MulRelinNew(ct0, ct1, rlk)
		}

	})
}

func benchMulOld(testctx *testContext, b *testing.B) {
	eval := testctx.evalOld

	_, ct0 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))
	_, ct1 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))

	b.Run("MulOld", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.MulRelinNew(ct0, ct1)
		}

	})
}
