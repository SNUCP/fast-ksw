package fckks

import (
	"fmt"
	"testing"
)

func BenchmarkFCKKS(b *testing.B) {

	paramList := []ParametersLiteral{PN15QP870, PN16QP1760}

	for _, paramsLiteral := range paramList {
		params := NewParametersFromLiteral(paramsLiteral)
		testctx, err := genTestParams(params)
		if err != nil {
			panic(err)
		}

		benchMulOld(testctx, b)
		benchMulNew(testctx, b)

		benchKeySwtichOld(testctx, b)
		benchKeySwitchNew(testctx, b)
	}
}

func benchMulNew(testctx *testContext, b *testing.B) {
	eval := testctx.eval
	rlk := testctx.rlk

	_, ct0 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))
	_, ct1 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))

	b.Run(fmt.Sprintf("MulNew logN:%d logQP:%d", testctx.params.LogN(), testctx.params.LogQP()), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.MulRelinNew(ct0, ct1, rlk)
		}

	})
}

func benchMulOld(testctx *testContext, b *testing.B) {
	eval := testctx.evalOld

	_, ct0 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))
	_, ct1 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))

	b.Run(fmt.Sprintf("MulOld logN:%d logQP:%d", testctx.params.LogN(), testctx.params.LogQP()), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.MulRelinNew(ct0, ct1)
		}

	})
}

func benchKeySwitchNew(testctx *testContext, b *testing.B) {
	eval := testctx.eval
	rlk := testctx.rlk

	_, ct0 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))

	testctx.ringQ.InvNTTLvl(ct0.Level(), ct0.Value[0], ct0.Value[0])
	testctx.ringQ.InvNTTLvl(ct0.Level(), ct0.Value[1], ct0.Value[1])

	ct0.Value[0].IsNTT = false
	ct0.Value[1].IsNTT = false

	b.Run(fmt.Sprintf("KeySwitchNew logN:%d logQP:%d", testctx.params.LogN(), testctx.params.LogQP()), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.SwitchKeysNew(ct0, rlk.Value)
		}
	})
}

func benchKeySwtichOld(testctx *testContext, b *testing.B) {
	eval := testctx.evalOld
	rlk := testctx.kgen.GenRelinearizationKey(testctx.sk, 1)

	_, ct0 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))

	testctx.ringQ.InvNTTLvl(ct0.Level(), ct0.Value[0], ct0.Value[0])
	testctx.ringQ.InvNTTLvl(ct0.Level(), ct0.Value[1], ct0.Value[1])

	ct0.Value[0].IsNTT = false
	ct0.Value[1].IsNTT = false

	b.Run(fmt.Sprintf("KeySwitchOld logN:%d logQP:%d", testctx.params.LogN(), testctx.params.LogQP()), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.SwitchKeysNew(ct0, rlk.Keys[0])
		}
	})
}
