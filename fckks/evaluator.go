package fckks

import (
	"fast-ksw/ckks"
	"fast-ksw/frlwe"
	"fast-ksw/ring"
	"fast-ksw/rlwe"
	"fast-ksw/utils"
	//"math/bits"
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

	eval.ksw.SwitchKey(ctOut.Level(), eval.polyQPool[0], rlk.Value[0], rlk.Value[1], eval.polyQPool[1], eval.polyQPool[2])

	ringQ.NTTLvl(ctOut.Level(), eval.polyQPool[1], eval.polyQPool[1])
	ringQ.NTTLvl(ctOut.Level(), eval.polyQPool[2], eval.polyQPool[2])

	ringQ.AddLvl(ctOut.Level(), eval.polyQPool[1], ctOut.Value[0], ctOut.Value[0])
	ringQ.AddLvl(ctOut.Level(), eval.polyQPool[2], ctOut.Value[1], ctOut.Value[1])

	ctOut.Value = ctOut.Value[:2]
}

func (eval *Evaluator) RotateNew(ctIn *ckks.Ciphertext, rtk *frlwe.RotationKey) (ctOut *ckks.Ciphertext) {
	ctOut = ckks.NewCiphertext(eval.params.Parameters, 1, ctIn.Level(), ctIn.Scale)
	eval.Rotate(ctIn, rtk, ctOut)
	return
}

func (eval *Evaluator) Rotate(ctIn *ckks.Ciphertext, rtk *frlwe.RotationKey, ctOut *ckks.Ciphertext) {

	ringQ := eval.params.RingQ()

	ringQ.InvNTTLvl(ctOut.Level(), ctIn.Value[1], eval.polyQPool[0])

	eval.ksw.SwitchKey(ctOut.Level(), eval.polyQPool[0], rtk.Value[0], rtk.Value[1], eval.polyQPool[1], eval.polyQPool[2])

	ringQ.NTTLvl(ctOut.Level(), eval.polyQPool[1], eval.polyQPool[1])
	ringQ.NTTLvl(ctOut.Level(), eval.polyQPool[2], eval.polyQPool[2])

	ringQ.AddLvl(ctOut.Level(), ctIn.Value[0], eval.polyQPool[1], eval.polyQPool[1])

	// permute ctOut

	galEl := eval.params.GaloisElementForColumnRotationBy(int(rtk.Rotidx))
	ringQ.PermuteNTTLvl(ctOut.Level(), eval.polyQPool[1], galEl, ctOut.Value[0])
	ringQ.PermuteNTTLvl(ctOut.Level(), eval.polyQPool[2], galEl, ctOut.Value[1])
}

func (eval *Evaluator) SwitchKeys(ct0 *ckks.Ciphertext, swk [2]*frlwe.SwitchingKey, ctOut *ckks.Ciphertext) {

	level := utils.MinInt(ct0.Level(), ctOut.Level())
	ringQ := eval.params.RingQ()

	ctOut.Scale = ct0.Scale

	eval.ksw.SwitchKey(level, ct0.Value[1], swk[0], swk[1], eval.polyQPool[1], eval.polyQPool[2])

	ringQ.AddLvl(level, ct0.Value[0], eval.polyQPool[1], ctOut.Value[0])
	ring.CopyValuesLvl(level, eval.polyQPool[2], ctOut.Value[1])
}

func (eval *Evaluator) SwitchKeysNew(ct0 *ckks.Ciphertext, swk [2]*frlwe.SwitchingKey) (ctOut *ckks.Ciphertext) {
	ctOut = ckks.NewCiphertext(eval.params.Parameters, ct0.Degree(), ct0.Level(), ct0.Scale)
	eval.SwitchKeys(ct0, swk, ctOut)
	return
}
