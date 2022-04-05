package fckks

import (
	"fast-ksw/frlwe"
	"github.com/tuneinsight/lattigo/v3/ckks"
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"github.com/tuneinsight/lattigo/v3/utils"
)

type Evaluator struct {
	ckks.Evaluator
	params    Parameters
	ksw       *frlwe.KeySwitcher
	polyQPool [4]*ring.Poly
}

func NewEvaluator(params Parameters) (eval *Evaluator) {
	eval = new(Evaluator)
	eval.params = params
	eval.ksw = frlwe.NewKeySwitcher(params.frlweParams)
	evalKey := rlwe.EvaluationKey{nil, nil}
	eval.Evaluator = ckks.NewEvaluator(params.Parameters, evalKey)

	for i := 0; i < len(eval.polyQPool); i++ {
		eval.polyQPool[i] = params.RingQ().NewPoly()
	}

	return
}

func (eval *Evaluator) AddNew(op0, op1 ckks.Operand) *ckks.Ciphertext {
	return eval.Evaluator.AddNew(op0, op1)
}

func (eval *Evaluator) Add(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	eval.Evaluator.Add(op0, op1, ctOut)
}

func (eval *Evaluator) SubNew(op0, op1 ckks.Operand) *ckks.Ciphertext {
	return eval.Evaluator.SubNew(op0, op1)
}

func (eval *Evaluator) Sub(op0, op1 ckks.Operand, ctOut *ckks.Ciphertext) {
	eval.Evaluator.Sub(op0, op1, ctOut)
}

func (eval *Evaluator) MulRelinNew(ct0, ct1 *ckks.Ciphertext, rlk *frlwe.RelinKey) (ctOut *ckks.Ciphertext) {
	ctOut = ckks.NewCiphertext(eval.params.Parameters, 2, utils.MinInt(ct0.Level(), ct1.Level()), 0)
	eval.MulRelin(ct0, ct1, rlk, ctOut)
	return
}

func (eval *Evaluator) MulRelin(ct0, ct1 *ckks.Ciphertext, rlk *frlwe.RelinKey, ctOut *ckks.Ciphertext) {
	eval.Evaluator.Mul(ct0, ct1, ctOut)

	ringQ := eval.params.RingQ()
	ringQ.InvNTTLvl(ctOut.Level(), ctOut.Value[2], eval.polyQPool[0])

	/*
		eval.ksw.InternalProduct(ctOut.Level(), eval.polyQPool[0], rlk.Value[0], eval.polyQPool[1])
		eval.ksw.InternalProduct(ctOut.Level(), eval.polyQPool[0], rlk.Value[1], eval.polyQPool[2])
	*/

	eval.ksw.SwitchKey(ctOut.Level(), eval.polyQPool[0], rlk.Value[0], rlk.Value[1], eval.polyQPool[1], eval.polyQPool[2])

	ringQ.NTTLazyLvl(ctOut.Level(), eval.polyQPool[1], eval.polyQPool[1])
	ringQ.NTTLazyLvl(ctOut.Level(), eval.polyQPool[2], eval.polyQPool[2])

	ringQ.AddLvl(ctOut.Level(), eval.polyQPool[1], ctOut.Value[0], ctOut.Value[0])
	ringQ.AddLvl(ctOut.Level(), eval.polyQPool[2], ctOut.Value[1], ctOut.Value[1])

	ctOut.Value = ctOut.Value[:2]

	//eval.Rescale(ctOut, eval.params.DefaultScale(), ctOut)
}
