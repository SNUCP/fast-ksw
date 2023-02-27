package ckks

import (
	"errors"
	"fmt"
	"math"

	"fast-ksw/ring"
	"fast-ksw/rlwe"
	"fast-ksw/utils"
)

// Operand is a common interface for Ciphertext and Plaintext types.
type Operand interface {
	El() *rlwe.Ciphertext
	Degree() int
	Level() int
	ScalingFactor() float64
	SetScalingFactor(float64)
}

// Evaluator is an interface implementing the methods to conduct homomorphic operations between ciphertext and/or plaintexts.
type Evaluator interface {
	// ========================
	// === Basic Arithmetic ===
	// ========================

	// Addition
	Add(op0, op1 Operand, ctOut *Ciphertext)
	AddNoMod(op0, op1 Operand, ctOut *Ciphertext)
	AddNew(op0, op1 Operand) (ctOut *Ciphertext)
	AddNoModNew(op0, op1 Operand) (ctOut *Ciphertext)

	// Subtraction
	Sub(op0, op1 Operand, ctOut *Ciphertext)
	SubNoMod(op0, op1 Operand, ctOut *Ciphertext)
	SubNew(op0, op1 Operand) (ctOut *Ciphertext)
	SubNoModNew(op0, op1 Operand) (ctOut *Ciphertext)

	// Negation
	Neg(ctIn *Ciphertext, ctOut *Ciphertext)
	NegNew(ctIn *Ciphertext) (ctOut *Ciphertext)

	// Constant Addition
	AddConstNew(ctIn *Ciphertext, constant interface{}) (ctOut *Ciphertext)
	AddConst(ctIn *Ciphertext, constant interface{}, ctOut *Ciphertext)

	// Constant Multiplication
	MultByConstNew(ctIn *Ciphertext, constant interface{}) (ctOut *Ciphertext)
	MultByConst(ctIn *Ciphertext, constant interface{}, ctOut *Ciphertext)
	MultByGaussianInteger(ctIn *Ciphertext, cReal, cImag interface{}, ctOut *Ciphertext)

	// Constant Multiplication with Addition
	MultByConstAndAdd(ctIn *Ciphertext, constant interface{}, ctOut *Ciphertext)
	MultByGaussianIntegerAndAdd(ctIn *Ciphertext, cReal, cImag interface{}, ctOut *Ciphertext)

	// Multiplication by the imaginary unit
	MultByiNew(ctIn *Ciphertext) (ctOut *Ciphertext)
	MultByi(ctIn *Ciphertext, ctOut *Ciphertext)
	DivByiNew(ctIn *Ciphertext) (ctOut *Ciphertext)
	DivByi(ctIn *Ciphertext, ctOut *Ciphertext)

	// Conjugation
	ConjugateNew(ctIn *Ciphertext) (ctOut *Ciphertext)
	Conjugate(ctIn *Ciphertext, ctOut *Ciphertext)

	// Multiplication
	Mul(op0, op1 Operand, ctOut *Ciphertext)
	MulNew(op0, op1 Operand) (ctOut *Ciphertext)
	MulRelin(op0, op1 Operand, ctOut *Ciphertext)
	MulRelinNew(op0, op1 Operand) (ctOut *Ciphertext)

	MulAndAdd(op0, op1 Operand, ctOut *Ciphertext)
	MulRelinAndAdd(op0, op1 Operand, ctOut *Ciphertext)

	// Rotate

	Rotate(ct0 *Ciphertext, k int, ctOut *Ciphertext)
	RotateNew(ct0 *Ciphertext, k int) (ctOut *Ciphertext)

	// =============================
	// === Ciphertext Management ===
	// =============================

	// Key-Switching
	SwitchKeysNew(ctIn *Ciphertext, switchingKey *rlwe.SwitchingKey) (ctOut *Ciphertext)
	SwitchKeys(ctIn *Ciphertext, switchingKey *rlwe.SwitchingKey, ctOut *Ciphertext)

	// Degree Management
	RelinearizeNew(ctIn *Ciphertext) (ctOut *Ciphertext)
	Relinearize(ctIn *Ciphertext, ctOut *Ciphertext)

	// Scale Management
	ScaleUpNew(ctIn *Ciphertext, scale float64) (ctOut *Ciphertext)
	ScaleUp(ctIn *Ciphertext, scale float64, ctOut *Ciphertext)
	SetScale(ctIn *Ciphertext, scale float64)
	Rescale(ctIn *Ciphertext, minScale float64, ctOut *Ciphertext) (err error)

	// Level Management
	DropLevelNew(ctIn *Ciphertext, levels int) (ctOut *Ciphertext)
	DropLevel(ctIn *Ciphertext, levels int)

	// Modular Overflow Management
	ReduceNew(ctIn *Ciphertext) (ctOut *Ciphertext)
	Reduce(ctIn *Ciphertext, ctOut *Ciphertext) error

	// ==============
	// === Others ===
	// ==============
	GetKeySwitcher() *rlwe.KeySwitcher
	PoolQMul() [3]*ring.Poly
	CtxPool() *Ciphertext
}

// evaluator is a struct that holds the necessary elements to execute the homomorphic operations between Ciphertexts and/or Plaintexts.
// It also holds a small memory pool used to store intermediate computations.
type evaluator struct {
	*evaluatorBase
	*evaluatorBuffers
	*rlwe.KeySwitcher

	rlk             *rlwe.RelinearizationKey
	rtks            *rlwe.RotationKeySet
	permuteNTTIndex map[uint64][]uint64
}

type evaluatorBase struct {
	params Parameters
}

type evaluatorBuffers struct {
	poolQMul [3]*ring.Poly // Memory pool in order : for MForm(c0), MForm(c1), c2
	ctxpool  *Ciphertext   // Memory pool for ciphertext that need to be scaled up (to be removed eventually)
}

// PoolQMul returns a pointer to internal memory pool poolQMul.
func (eval *evaluator) PoolQMul() [3]*ring.Poly {
	return eval.poolQMul
}

// CtxPool returns a pointer to internal memory pool CtxPool.
func (eval *evaluator) CtxPool() *Ciphertext {
	return eval.ctxpool
}

func newEvaluatorBase(params Parameters) *evaluatorBase {
	ev := new(evaluatorBase)
	ev.params = params
	return ev
}

func newEvaluatorBuffers(evalBase *evaluatorBase) *evaluatorBuffers {
	buff := new(evaluatorBuffers)
	params := evalBase.params
	ringQ := params.RingQ()
	buff.poolQMul = [3]*ring.Poly{ringQ.NewPoly(), ringQ.NewPoly(), ringQ.NewPoly()}
	buff.ctxpool = NewCiphertext(params, 2, params.MaxLevel(), params.DefaultScale())
	return buff
}

// NewEvaluator creates a new Evaluator, that can be used to do homomorphic
// operations on the Ciphertexts and/or Plaintexts. It stores a small pool of polynomials
// and Ciphertexts that will be used for intermediate values.
func NewEvaluator(params Parameters, evaluationKey rlwe.EvaluationKey) Evaluator {
	eval := new(evaluator)
	eval.evaluatorBase = newEvaluatorBase(params)
	eval.evaluatorBuffers = newEvaluatorBuffers(eval.evaluatorBase)

	eval.rlk = evaluationKey.Rlk
	eval.rtks = evaluationKey.Rtks
	if eval.rtks != nil {
		eval.permuteNTTIndex = *eval.permuteNTTIndexesForKey(eval.rtks)
	}

	if params.PCount() != 0 {
		eval.KeySwitcher = rlwe.NewKeySwitcher(params.Parameters)
	}

	return eval
}

func (eval *evaluator) permuteNTTIndexesForKey(rtks *rlwe.RotationKeySet) *map[uint64][]uint64 {
	if rtks == nil {
		return &map[uint64][]uint64{}
	}
	permuteNTTIndex := make(map[uint64][]uint64, len(rtks.Keys))
	for galEl := range rtks.Keys {
		permuteNTTIndex[galEl] = eval.params.RingQ().PermuteNTTIndex(galEl)
	}
	return &permuteNTTIndex
}

// GetKeySwitcher returns a pointer to the internal rlwe.KeySwither.
func (eval *evaluator) GetKeySwitcher() *rlwe.KeySwitcher {
	return eval.KeySwitcher
}

func (eval *evaluator) checkBinary(op0, op1, opOut Operand, opOutMinDegree int) {
	if op0 == nil || op1 == nil || opOut == nil {
		panic("operands cannot be nil")
	}

	if op0.Degree()+op1.Degree() == 0 {
		panic("operands cannot be both plaintext")
	}

	if opOut.Degree() < opOutMinDegree {
		panic("receiver operand degree is too small")
	}

	for _, pol := range op0.El().Value {
		if !pol.IsNTT {
			panic("cannot evaluate: op0 must be in NTT")
		}
	}

	for _, pol := range op1.El().Value {
		if !pol.IsNTT {
			panic("cannot evaluate: op1 must be in NTT")
		}
	}

	return
}

func (eval *evaluator) newCiphertextBinary(op0, op1 Operand) (ctOut *Ciphertext) {

	maxDegree := utils.MaxInt(op0.Degree(), op1.Degree())
	maxScale := utils.MaxFloat64(op0.ScalingFactor(), op1.ScalingFactor())
	minLevel := utils.MinInt(op0.Level(), op1.Level())

	return NewCiphertext(eval.params, maxDegree, minLevel, maxScale)
}

// Add adds op0 to op1 and returns the result in ctOut.
func (eval *evaluator) Add(op0, op1 Operand, ctOut *Ciphertext) {
	eval.checkBinary(op0, op1, ctOut, utils.MaxInt(op0.Degree(), op1.Degree()))
	eval.evaluateInPlace(op0, op1, ctOut, eval.params.RingQ().AddLvl)
}

// AddNoMod adds op0 to op1 and returns the result in ctOut, without modular reduction.
func (eval *evaluator) AddNoMod(op0, op1 Operand, ctOut *Ciphertext) {
	eval.checkBinary(op0, op1, ctOut, utils.MaxInt(op0.Degree(), op1.Degree()))
	eval.evaluateInPlace(op0, op1, ctOut, eval.params.RingQ().AddNoModLvl)
}

// AddNew adds op0 to op1 and returns the result in a newly created element.
func (eval *evaluator) AddNew(op0, op1 Operand) (ctOut *Ciphertext) {
	ctOut = eval.newCiphertextBinary(op0, op1)
	eval.Add(op0, op1, ctOut)
	return
}

// AddNoModNew adds op0 to op1 without modular reduction, and returns the result in a newly created element.
func (eval *evaluator) AddNoModNew(op0, op1 Operand) (ctOut *Ciphertext) {
	ctOut = eval.newCiphertextBinary(op0, op1)
	eval.AddNoMod(op0, op1, ctOut)
	return
}

// Sub subtracts op1 from op0 and returns the result in ctOut.
func (eval *evaluator) Sub(op0, op1 Operand, ctOut *Ciphertext) {

	eval.checkBinary(op0, op1, ctOut, utils.MaxInt(op0.Degree(), op1.Degree()))

	eval.evaluateInPlace(op0, op1, ctOut, eval.params.RingQ().SubLvl)

	level := utils.MinInt(utils.MinInt(op0.Level(), op1.Level()), ctOut.Level())

	if op0.Degree() < op1.Degree() {
		for i := op0.Degree() + 1; i < op1.Degree()+1; i++ {
			eval.params.RingQ().NegLvl(level, ctOut.Value[i], ctOut.Value[i])
		}
	}

}

// SubNoMod subtracts op1 from op0 and returns the result in ctOut, without modular reduction.
func (eval *evaluator) SubNoMod(op0, op1 Operand, ctOut *Ciphertext) {

	eval.checkBinary(op0, op1, ctOut, utils.MaxInt(op0.Degree(), op1.Degree()))

	eval.evaluateInPlace(op0, op1, ctOut, eval.params.RingQ().SubNoModLvl)

	level := utils.MinInt(utils.MinInt(op0.Level(), op1.Level()), ctOut.Level())

	if op0.Degree() < op1.Degree() {
		for i := op0.Degree() + 1; i < op1.Degree()+1; i++ {
			eval.params.RingQ().NegLvl(level, ctOut.Value[i], ctOut.Value[i])
		}
	}

}

// SubNew subtracts op1 from op0 and returns the result in a newly created element.
func (eval *evaluator) SubNew(op0, op1 Operand) (ctOut *Ciphertext) {
	ctOut = eval.newCiphertextBinary(op0, op1)
	eval.Sub(op0, op1, ctOut)
	return
}

// SubNoModNew subtracts op1 from op0 without modular reduction, and returns the result in a newly created element.
func (eval *evaluator) SubNoModNew(op0, op1 Operand) (ctOut *Ciphertext) {
	ctOut = eval.newCiphertextBinary(op0, op1)
	eval.SubNoMod(op0, op1, ctOut)
	return
}

func (eval *evaluator) evaluateInPlace(c0, c1, ctOut Operand, evaluate func(int, *ring.Poly, *ring.Poly, *ring.Poly)) {

	var tmp0, tmp1 *rlwe.Ciphertext

	level := utils.MinInt(utils.MinInt(c0.Level(), c1.Level()), ctOut.Level())

	maxDegree := utils.MaxInt(c0.Degree(), c1.Degree())
	minDegree := utils.MinInt(c0.Degree(), c1.Degree())

	// Else resizes the receiver element
	ctOut.El().Resize(eval.params.Parameters, maxDegree)

	c0Scale := c0.ScalingFactor()
	c1Scale := c1.ScalingFactor()
	ctOutScale := ctOut.ScalingFactor()

	if ctOut.Level() > level {
		eval.DropLevel(&Ciphertext{ctOut.El(), ctOutScale}, ctOut.Level()-utils.MinInt(c0.Level(), c1.Level()))
	}

	// Checks whether or not the receiver element is the same as one of the input elements
	// and acts accordingly to avoid unnecessary element creation or element overwriting,
	// and scales properly the element before the evaluation.
	if ctOut == c0 {

		if c0Scale > c1Scale && math.Floor(c0Scale/c1Scale) > 1 {

			tmp1 = eval.ctxpool.El()

			eval.MultByConst(&Ciphertext{c1.El(), c1Scale}, math.Floor(c0Scale/c1Scale), &Ciphertext{tmp1, ctOutScale})

		} else if c1Scale > c0Scale && math.Floor(c1Scale/c0Scale) > 1 {

			eval.MultByConst(&Ciphertext{c0.El(), c0Scale}, math.Floor(c1Scale/c0Scale), &Ciphertext{c0.El(), c0Scale})

			ctOut.SetScalingFactor(c1Scale)

			tmp1 = c1.El()

		} else {

			tmp1 = c1.El()
		}

		tmp0 = c0.El()

	} else if ctOut == c1 {

		if c1Scale > c0Scale && math.Floor(c1Scale/c0Scale) > 1 {

			tmp0 = eval.ctxpool.El()

			eval.MultByConst(&Ciphertext{c0.El(), c0Scale}, math.Floor(c1Scale/c0Scale), &Ciphertext{tmp0, ctOutScale})

		} else if c0Scale > c1Scale && math.Floor(c0Scale/c1Scale) > 1 {

			eval.MultByConst(&Ciphertext{c1.El(), c1Scale}, math.Floor(c0Scale/c1Scale), &Ciphertext{ctOut.El(), ctOutScale})

			ctOut.SetScalingFactor(c0Scale)

			tmp0 = c0.El()

		} else {

			tmp0 = c0.El()
		}

		tmp1 = c1.El()

	} else {

		if c1Scale > c0Scale && math.Floor(c1Scale/c0Scale) > 1 {

			tmp0 = eval.ctxpool.El()

			eval.MultByConst(&Ciphertext{c0.El(), c0Scale}, math.Floor(c1Scale/c0Scale), &Ciphertext{tmp0, ctOutScale})

			tmp1 = c1.El()

		} else if c0Scale > c1Scale && math.Floor(c0Scale/c1Scale) > 1 {

			tmp1 = eval.ctxpool.El()

			eval.MultByConst(&Ciphertext{c1.El(), c1Scale}, math.Floor(c0Scale/c1Scale), &Ciphertext{tmp1, ctOutScale})

			tmp0 = c0.El()

		} else {
			tmp0 = c0.El()
			tmp1 = c1.El()
		}
	}

	for i := 0; i < minDegree+1; i++ {
		evaluate(level, tmp0.Value[i], tmp1.Value[i], ctOut.El().Value[i])
	}

	ctOut.SetScalingFactor(utils.MaxFloat64(c0Scale, c1Scale))

	// If the inputs degrees differ, it copies the remaining degree on the receiver.
	// Also checks that the receiver is not one of the inputs to avoid unnecessary work.

	if c0.Degree() > c1.Degree() && tmp0 != ctOut.El() {
		for i := minDegree + 1; i < maxDegree+1; i++ {
			ring.CopyValuesLvl(level, tmp0.Value[i], ctOut.El().Value[i])
		}
	} else if c1.Degree() > c0.Degree() && tmp1 != ctOut.El() {
		for i := minDegree + 1; i < maxDegree+1; i++ {
			ring.CopyValuesLvl(level, tmp1.Value[i], ctOut.El().Value[i])
		}
	}
}

// Neg negates the value of ct0 and returns the result in ctOut.
func (eval *evaluator) Neg(ct0 *Ciphertext, ctOut *Ciphertext) {

	level := utils.MinInt(ct0.Level(), ctOut.Level())

	if ct0.Degree() != ctOut.Degree() {
		panic("cannot Negate: invalid receiver Ciphertext does not match input Ciphertext degree")
	}

	for i := range ct0.Value {
		eval.params.RingQ().NegLvl(level, ct0.Value[i], ctOut.Value[i])
	}

	ctOut.Scale = ct0.Scale
}

// NegNew negates ct0 and returns the result in a newly created element.
func (eval *evaluator) NegNew(ct0 *Ciphertext) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, ct0.Degree(), ct0.Level(), ct0.Scale)
	eval.Neg(ct0, ctOut)
	return
}

// AddConstNew adds the input constant (which can be a uint64, int64, float64 or complex128) to ct0 and returns the result in a new element.
func (eval *evaluator) AddConstNew(ct0 *Ciphertext, constant interface{}) (ctOut *Ciphertext) {
	ctOut = ct0.CopyNew()
	eval.AddConst(ct0, constant, ctOut)
	return ctOut
}

func (eval *evaluator) getConstAndScale(level int, constant interface{}) (cReal, cImag, scale float64) {

	// Converts to float64 and determines if a scaling is required (which is the case if either real or imag have a rational part)
	scale = 1
	switch constant := constant.(type) {
	case complex128:
		cReal = real(constant)
		cImag = imag(constant)

		if cReal != 0 {
			valueInt := int64(cReal)
			valueFloat := cReal - float64(valueInt)

			if valueFloat != 0 {
				scale = float64(eval.params.RingQ().Modulus[level])
			}
		}

		if cImag != 0 {
			valueInt := int64(cImag)
			valueFloat := cImag - float64(valueInt)

			if valueFloat != 0 {
				scale = float64(eval.params.RingQ().Modulus[level])
			}
		}

	case float64:
		cReal = constant
		cImag = float64(0)

		if cReal != 0 {
			valueInt := int64(cReal)
			valueFloat := cReal - float64(valueInt)

			if valueFloat != 0 {
				scale = float64(eval.params.RingQ().Modulus[level])
			}
		}

	case uint64:
		cReal = float64(constant)
		cImag = float64(0)

	case int64:
		cReal = float64(constant)
		cImag = float64(0)

	case int:
		cReal = float64(constant)
		cImag = float64(0)
	}

	if eval.params.RingType() == ring.ConjugateInvariant {
		cImag = float64(0)
	}

	return
}

// AddConst adds the input constant (which can be a uint64, int64, float64 or complex128) to ct0 and returns the result in ctOut.
func (eval *evaluator) AddConst(ct0 *Ciphertext, constant interface{}, ctOut *Ciphertext) {

	var level = utils.MinInt(ct0.Level(), ctOut.Level())
	var scaledConst, scaledConstReal, scaledConstImag, qi uint64

	cReal, cImag, _ := eval.getConstAndScale(level, constant)

	ringQ := eval.params.RingQ()

	ctOut.Scale = ct0.Scale

	// Component wise addition of the following vector to the ciphertext:
	// [a + b*psi_qi^2, ....., a + b*psi_qi^2, a - b*psi_qi^2, ...., a - b*psi_qi^2] mod Qi
	// [{                  N/2                }{                N/2               }]
	// Which is equivalent outside of the NTT domain to adding a to the first coefficient of ct0 and b to the N/2-th coefficient of ct0.
	for i := 0; i < level+1; i++ {
		scaledConstReal, scaledConstImag, scaledConst = 0, 0, 0
		qi = ringQ.Modulus[i]

		if cReal != 0 {
			scaledConstReal = scaleUpExact(cReal, ctOut.Scale, qi)
			scaledConst = scaledConstReal
		}

		if cImag != 0 {
			scaledConstImag = ring.MRed(scaleUpExact(cImag, ctOut.Scale, qi), ringQ.NttPsi[i][1], qi, ringQ.MredParams[i])
			scaledConst = ring.CRed(scaledConst+scaledConstImag, qi)
		}

		p0tmp := ct0.Value[0].Coeffs[i]
		p1tmp := ctOut.Value[0].Coeffs[i]

		ring.AddScalarVec(p0tmp[:ringQ.N>>1], p1tmp[:ringQ.N>>1], scaledConst, qi)

		if cImag != 0 {
			scaledConst = ring.CRed(scaledConstReal+(qi-scaledConstImag), qi)
		}

		ring.AddScalarVec(p0tmp[ringQ.N>>1:], p1tmp[ringQ.N>>1:], scaledConst, qi)
	}
}

// MultByConstAndAdd multiplies ct0 by the input constant, and adds it to the receiver element (it does not modify the input
// element), e.g., ctOut(x) = ctOut(x) + ct0(x) * (a+bi). This functions removes the need of storing the intermediate value c(x) * (a+bi).
// This function will modify the level and the scale of the receiver element depending on the level and the scale of the input
// element and the type of the constant. The level of the receiver element will be set to min(input.level, receiver.level).
// The scale of the receiver element will be set to the scale that the input element would have after the multiplication by the constant.
func (eval *evaluator) MultByConstAndAdd(ct0 *Ciphertext, constant interface{}, ctOut *Ciphertext) {

	var level = utils.MinInt(ct0.Level(), ctOut.Level())

	// Forces a drop of ctOut level to ct0 level
	if ctOut.Level() > level {
		eval.DropLevel(ctOut, ctOut.Level()-level)
	}

	cReal, cImag, scale := eval.getConstAndScale(level, constant)

	var scaledConst, scaledConstReal, scaledConstImag uint64

	ringQ := eval.params.RingQ()

	// If a scaling would be required to multiply by the constant,
	// it equalizes scales such that the scales match in the end.
	if scale != 1 {

		// If ctOut scaling is smaller than ct0's scale + the default scaling,
		// then brings ctOut scale to ct0's scale.
		if ctOut.Scale < ct0.Scale*scale {

			if scale := math.Floor((scale * ct0.Scale) / ctOut.Scale); scale > 1 {

				eval.MultByConst(ctOut, scale, ctOut)

			}

			ctOut.Scale = scale * ct0.Scale

			// If ctOut.Scale > ((a+bi)*scale)*ct0(x), then it sets the scale to
			// bring c(x)*scale to the level of ctOut(x) scale
		} else if ctOut.Scale > ct0.Scale*scale {
			scale = ctOut.Scale / ct0.Scale
		}

		// If no scaling is required, then it sets the appropriate scale such that
		// ct0(x)*scale matches ctOut(x) scale without modifying ct0(x) scale.
	} else {

		if ctOut.Scale > ct0.Scale {

			scale = ctOut.Scale / ct0.Scale

		} else if ct0.Scale > ctOut.Scale {

			if scale := math.Floor(ct0.Scale / ctOut.Scale); scale > 1 {
				eval.MultByConst(ctOut, scale, ctOut)
			}

			ctOut.Scale = ct0.Scale
		}
	}

	// Component-wise multiplication of the following vector to the ciphertext:
	// [a + b*psi_qi^2, ....., a + b*psi_qi^2, a - b*psi_qi^2, ...., a - b*psi_qi^2] mod Qi
	// [{                  N/2                }{                N/2               }]
	// Which is equivalent outside of the NTT domain to adding a to the first coefficient of ct0 and b to the N/2-th coefficient of ct0.
	for i := 0; i < level+1; i++ {

		qi := ringQ.Modulus[i]
		mredParams := ringQ.MredParams[i]
		bredParams := ringQ.BredParams[i]

		scaledConstReal = 0
		scaledConstImag = 0
		scaledConst = 0

		if cReal != 0 {
			scaledConstReal = scaleUpExact(cReal, scale, qi)
			scaledConst = scaledConstReal
		}

		if cImag != 0 {
			scaledConstImag = scaleUpExact(cImag, scale, qi)
			scaledConstImag = ring.MRed(scaledConstImag, ringQ.NttPsi[i][1], qi, mredParams)
			scaledConst = ring.CRed(scaledConst+scaledConstImag, qi)
		}

		scaledConst = ring.MForm(scaledConst, qi, bredParams)

		for u := range ct0.Value {
			p0tmp := ct0.Value[u].Coeffs[i]
			p1tmp := ctOut.Value[u].Coeffs[i]
			ring.MulScalarMontgomeryAndAddVec(p0tmp[:ringQ.N>>1], p1tmp[:ringQ.N>>1], scaledConst, qi, mredParams)
		}

		if cImag != 0 {
			scaledConst = ring.CRed(scaledConstReal+(qi-scaledConstImag), qi)
			scaledConst = ring.MForm(scaledConst, qi, bredParams)
		}

		for u := range ct0.Value {
			p0tmp := ct0.Value[u].Coeffs[i]
			p1tmp := ctOut.Value[u].Coeffs[i]
			ring.MulScalarMontgomeryAndAddVec(p0tmp[ringQ.N>>1:], p1tmp[ringQ.N>>1:], scaledConst, qi, mredParams)
		}
	}
}

// MultByConstNew multiplies ct0 by the input constant and returns the result in a newly created element.
// The scale of the output element will depend on the scale of the input element and the constant (if the constant
// needs to be scaled (its rational part is not zero)). The constant can be a uint64, int64, float64 or complex128.
func (eval *evaluator) MultByConstNew(ct0 *Ciphertext, constant interface{}) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, ct0.Degree(), ct0.Level(), ct0.Scale)
	eval.MultByConst(ct0, constant, ctOut)
	return
}

// MultByConst multiplies ct0 by the input constant and returns the result in ctOut.
// The scale of the output element will depend on the scale of the input element and the constant (if the constant
// needs to be scaled (its rational part is not zero)). The constant can be a uint64, int64, float64 or complex128.
func (eval *evaluator) MultByConst(ct0 *Ciphertext, constant interface{}, ctOut *Ciphertext) {

	var level = utils.MinInt(ct0.Level(), ctOut.Level())

	cReal, cImag, scale := eval.getConstAndScale(level, constant)

	// Component wise multiplication of the following vector with the ciphertext:
	// [a + b*psi_qi^2, ....., a + b*psi_qi^2, a - b*psi_qi^2, ...., a - b*psi_qi^2] mod Qi
	// [{                  N/2                }{                N/2               }]
	// Which is equivalent outside of the NTT domain to adding a to the first coefficient of ct0 and b to the N/2-th coefficient of ct0.
	ringQ := eval.params.RingQ()
	var scaledConst, scaledConstReal, scaledConstImag uint64
	for i := 0; i < level+1; i++ {

		qi := ringQ.Modulus[i]
		bredParams := ringQ.BredParams[i]
		mredParams := ringQ.MredParams[i]

		scaledConstReal = 0
		scaledConstImag = 0
		scaledConst = 0

		if cReal != 0 {
			scaledConstReal = scaleUpExact(cReal, scale, qi)
			scaledConst = scaledConstReal
		}

		if cImag != 0 {
			scaledConstImag = scaleUpExact(cImag, scale, qi)
			scaledConstImag = ring.MRed(scaledConstImag, ringQ.NttPsi[i][1], qi, mredParams)
			scaledConst = ring.CRed(scaledConst+scaledConstImag, qi)
		}

		scaledConst = ring.MForm(scaledConst, qi, bredParams)

		for u := range ct0.Value {
			p0tmp := ct0.Value[u].Coeffs[i]
			p1tmp := ctOut.Value[u].Coeffs[i]
			ring.MulScalarMontgomeryVec(p0tmp[:ringQ.N>>1], p1tmp[:ringQ.N>>1], scaledConst, qi, mredParams)
		}

		if cImag != 0 {
			scaledConst = ring.CRed(scaledConstReal+(qi-scaledConstImag), qi)
			scaledConst = ring.MForm(scaledConst, qi, bredParams)
		}

		for u := range ct0.Value {
			p0tmp := ct0.Value[u].Coeffs[i]
			p1tmp := ctOut.Value[u].Coeffs[i]
			ring.MulScalarMontgomeryVec(p0tmp[ringQ.N>>1:], p1tmp[ringQ.N>>1:], scaledConst, qi, mredParams)
		}
	}

	ctOut.Scale = ct0.Scale * scale
}

// MultByGaussianInteger multiples the ct0 by the gaussian integer cReal + i*cImag and returns the result on ctOut.
// Accepted types for cReal and cImag are uint64, int64 and big.Int.
func (eval *evaluator) MultByGaussianInteger(ct0 *Ciphertext, cReal, cImag interface{}, ctOut *Ciphertext) {

	ringQ := eval.params.RingQ()

	level := utils.MinInt(ct0.Level(), ctOut.Level())
	var scaledConst, scaledConstReal, scaledConstImag uint64

	ctOut.Scale = ct0.Scale

	for i := 0; i < level+1; i++ {

		qi := ringQ.Modulus[i]
		bredParams := ringQ.BredParams[i]
		mredParams := ringQ.MredParams[i]

		scaledConstReal = interfaceMod(cReal, qi)

		if eval.params.RingType() != ring.ConjugateInvariant {
			scaledConstImag = interfaceMod(cImag, qi)
		}

		scaledConst = scaledConstReal

		if scaledConstImag != 0 {
			scaledConstImag = ring.MRed(scaledConstImag, ringQ.NttPsi[i][1], qi, mredParams)
			scaledConst = ring.CRed(scaledConst+scaledConstImag, qi)
		}

		scaledConst = ring.MForm(scaledConst, qi, bredParams)

		for u := range ct0.Value {
			p0tmp := ct0.Value[u].Coeffs[i]
			p1tmp := ctOut.Value[u].Coeffs[i]
			ring.MulScalarMontgomeryVec(p0tmp[:ringQ.N>>1], p1tmp[:ringQ.N>>1], scaledConst, qi, mredParams)
		}

		if cImag != 0 {
			scaledConst = ring.CRed(scaledConstReal+(qi-scaledConstImag), qi)
			scaledConst = ring.MForm(scaledConst, qi, bredParams)
		}

		for u := range ct0.Value {
			p0tmp := ct0.Value[u].Coeffs[i]
			p1tmp := ctOut.Value[u].Coeffs[i]
			ring.MulScalarMontgomeryVec(p0tmp[ringQ.N>>1:], p1tmp[ringQ.N>>1:], scaledConst, qi, mredParams)
		}
	}
}

// MultByGaussianIntegerAndAdd multiples the ct0 by the gaussian integer cReal + i*cImag and adds the result on ctOut.
// Accepted types for cReal and cImag are uint64, int64 and big.Int.
func (eval *evaluator) MultByGaussianIntegerAndAdd(ct0 *Ciphertext, cReal, cImag interface{}, ctOut *Ciphertext) {

	ringQ := eval.params.RingQ()

	level := utils.MinInt(ct0.Level(), ctOut.Level())
	var scaledConst, scaledConstReal, scaledConstImag uint64

	for i := 0; i < level+1; i++ {

		qi := ringQ.Modulus[i]
		bredParams := ringQ.BredParams[i]
		mredParams := ringQ.MredParams[i]

		scaledConstReal = interfaceMod(cReal, qi)

		if eval.params.RingType() != ring.ConjugateInvariant {
			scaledConstImag = interfaceMod(cImag, qi)
		}

		scaledConst = scaledConstReal

		if scaledConstImag != 0 {
			scaledConstImag = ring.MRed(scaledConstImag, ringQ.NttPsi[i][1], qi, mredParams)
			scaledConst = ring.CRed(scaledConst+scaledConstImag, qi)
		}

		scaledConst = ring.MForm(scaledConst, qi, bredParams)

		for u := range ct0.Value {
			p0tmp := ct0.Value[u].Coeffs[i]
			p1tmp := ctOut.Value[u].Coeffs[i]
			ring.MulScalarMontgomeryAndAddVec(p0tmp[:ringQ.N>>1], p1tmp[:ringQ.N>>1], scaledConst, qi, mredParams)
		}

		if cImag != 0 {
			scaledConst = ring.CRed(scaledConstReal+(qi-scaledConstImag), qi)
			scaledConst = ring.MForm(scaledConst, qi, bredParams)
		}

		for u := range ct0.Value {
			p0tmp := ct0.Value[u].Coeffs[i]
			p1tmp := ctOut.Value[u].Coeffs[i]
			ring.MulScalarMontgomeryAndAddVec(p0tmp[ringQ.N>>1:], p1tmp[ringQ.N>>1:], scaledConst, qi, mredParams)
		}
	}
}

// MultByiNew multiplies ct0 by the imaginary number i, and returns the result in a newly created element.
// It does not change the scale.
func (eval *evaluator) MultByiNew(ct0 *Ciphertext) (ctOut *Ciphertext) {

	if eval.params.RingType() == ring.ConjugateInvariant {
		panic("method MultByi is not supported when params.RingType() == ring.ConjugateInvariant")
	}

	ctOut = NewCiphertext(eval.params, 1, ct0.Level(), ct0.Scale)
	eval.MultByi(ct0, ctOut)
	return ctOut
}

// MultByi multiplies ct0 by the imaginary number i, and returns the result in ctOut.
// It does not change the scale.
func (eval *evaluator) MultByi(ct0 *Ciphertext, ctOut *Ciphertext) {

	if eval.params.RingType() == ring.ConjugateInvariant {
		panic("method MultByi is not supported when params.RingType() == ring.ConjugateInvariant")
	}

	var level = utils.MinInt(ct0.Level(), ctOut.Level())
	ctOut.Scale = ct0.Scale

	ringQ := eval.params.RingQ()

	var imag uint64

	// Equivalent to a product by the monomial x^(n/2) outside of the NTT domain
	for i := 0; i < level+1; i++ {

		qi := ringQ.Modulus[i]
		mredParams := ringQ.MredParams[i]

		imag = ringQ.NttPsi[i][1] // Psi^2

		for u := range ctOut.Value {
			p0tmp := ct0.Value[u].Coeffs[i]
			p1tmp := ctOut.Value[u].Coeffs[i]
			ring.MulScalarMontgomeryVec(p0tmp[:ringQ.N>>1], p1tmp[:ringQ.N>>1], imag, qi, mredParams)
		}

		imag = qi - imag

		for u := range ctOut.Value {
			p0tmp := ct0.Value[u].Coeffs[i]
			p1tmp := ctOut.Value[u].Coeffs[i]
			ring.MulScalarMontgomeryVec(p0tmp[ringQ.N>>1:], p1tmp[ringQ.N>>1:], imag, qi, mredParams)
		}
	}
}

// DivByiNew multiplies ct0 by the imaginary number 1/i = -i, and returns the result in a newly created element.
// It does not change the scale.
func (eval *evaluator) DivByiNew(ct0 *Ciphertext) (ctOut *Ciphertext) {

	if eval.params.RingType() == ring.ConjugateInvariant {
		panic("method DivByi is not supported when params.RingType() == ring.ConjugateInvariant")
	}

	ctOut = NewCiphertext(eval.params, 1, ct0.Level(), ct0.Scale)
	eval.DivByi(ct0, ctOut)
	return
}

// DivByi multiplies ct0 by the imaginary number 1/i = -i, and returns the result in ctOut.
// It does not change the scale.
func (eval *evaluator) DivByi(ct0 *Ciphertext, ctOut *Ciphertext) {

	if eval.params.RingType() == ring.ConjugateInvariant {
		panic("method DivByi is not supported when params.RingType() == ring.ConjugateInvariant")
	}

	var level = utils.MinInt(ct0.Level(), ctOut.Level())

	ringQ := eval.params.RingQ()

	ctOut.Scale = ct0.Scale

	var imag uint64

	// Equivalent to a product by the monomial x^(3*n/2) outside of the NTT domain
	for i := 0; i < level+1; i++ {

		qi := ringQ.Modulus[i]
		mredParams := ringQ.MredParams[i]

		imag = qi - ringQ.NttPsi[i][1] // -Psi^2

		for u := range ctOut.Value {
			p0tmp := ct0.Value[u].Coeffs[i]
			p1tmp := ctOut.Value[u].Coeffs[i]
			ring.MulScalarMontgomeryVec(p0tmp[:ringQ.N>>1], p1tmp[:ringQ.N>>1], imag, qi, mredParams)
		}

		imag = ringQ.NttPsi[i][1] // Psi^2

		for u := range ctOut.Value {
			p0tmp := ct0.Value[u].Coeffs[i]
			p1tmp := ctOut.Value[u].Coeffs[i]
			ring.MulScalarMontgomeryVec(p0tmp[ringQ.N>>1:], p1tmp[ringQ.N>>1:], imag, qi, mredParams)
		}
	}
}

// ScaleUpNew multiplies ct0 by 2^scale and sets its scale to its previous scale
// plus 2^n. It returns the result in a newly created element.
func (eval *evaluator) ScaleUpNew(ct0 *Ciphertext, scale float64) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, ct0.Degree(), ct0.Level(), ct0.Scale)
	eval.ScaleUp(ct0, scale, ctOut)
	return
}

// ScaleUp multiplies ct0 by 2^scale and sets its scale to its previous scale
// plus 2^n. It returns the result in ctOut.
func (eval *evaluator) ScaleUp(ct0 *Ciphertext, scale float64, ctOut *Ciphertext) {
	eval.MultByConst(ct0, uint64(scale), ctOut)
	ctOut.Scale = ct0.Scale * scale
}

// SetScale sets the scale of the ciphertext to the input scale (consumes a level)
func (eval *evaluator) SetScale(ct *Ciphertext, scale float64) {
	eval.MultByConst(ct, scale/ct.Scale, ct)
	if err := eval.Rescale(ct, scale, ct); err != nil {
		panic(err)
	}
	ct.Scale = scale
}

// MulByPow2New multiplies ct0 by 2^pow2 and returns the result in a newly created element.
func (eval *evaluator) MulByPow2New(ct0 *Ciphertext, pow2 int) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, ct0.Degree(), ct0.Level(), ct0.Scale)
	eval.MulByPow2(ct0, pow2, ctOut)
	return
}

// MulByPow2 multiplies ct0 by 2^pow2 and returns the result in ctOut.
func (eval *evaluator) MulByPow2(ct0 *Ciphertext, pow2 int, ctOut *Ciphertext) {
	var level = utils.MinInt(ct0.Level(), ctOut.Level())
	ctOut.Scale = ct0.Scale
	for i := range ctOut.Value {
		eval.params.RingQ().MulByPow2Lvl(level, ct0.Value[i], pow2, ctOut.Value[i])
	}
}

// ReduceNew applies a modular reduction to ct0 and returns the result in a newly created element.
// To be used in conjunction with functions that do not apply modular reduction.
func (eval *evaluator) ReduceNew(ct0 *Ciphertext) (ctOut *Ciphertext) {

	ctOut = NewCiphertext(eval.params, ct0.Degree(), ct0.Level(), ct0.Scale)

	_ = eval.Reduce(ct0, ctOut)

	return ctOut
}

// Reduce applies a modular reduction to ct0 and returns the result in ctOut.
// To be used in conjunction with functions that do not apply modular reduction.
func (eval *evaluator) Reduce(ct0 *Ciphertext, ctOut *Ciphertext) error {

	if ct0.Degree() != ctOut.Degree() {
		return errors.New("cannot Reduce: degrees of receiver Ciphertext and input Ciphertext do not match")
	}

	for i := range ct0.Value {
		eval.params.RingQ().ReduceLvl(utils.MinInt(ct0.Level(), ctOut.Level()), ct0.Value[i], ctOut.Value[i])
	}

	ctOut.Scale = ct0.Scale

	return nil
}

// DropLevelNew reduces the level of ct0 by levels and returns the result in a newly created element.
// No rescaling is applied during this procedure.
func (eval *evaluator) DropLevelNew(ct0 *Ciphertext, levels int) (ctOut *Ciphertext) {
	ctOut = ct0.CopyNew()
	eval.DropLevel(ctOut, levels)
	return
}

// DropLevel reduces the level of ct0 by levels and returns the result in ct0.
// No rescaling is applied during this procedure.
func (eval *evaluator) DropLevel(ct0 *Ciphertext, levels int) {
	level := ct0.Level()
	for i := range ct0.Value {
		ct0.Value[i].Coeffs = ct0.Value[i].Coeffs[:level+1-levels]
	}
}

// RescaleNew divides ct0 by the last modulus in the moduli chain, and repeats this
// procedure (consuming one level each time) until the scale reaches the original scale or before it goes below it, and returns the result
// in a newly created element. Since all the moduli in the moduli chain are generated to be close to the
// original scale, this procedure is equivalent to dividing the input element by the scale and adding
// some error.
// Returns an error if "threshold <= 0", ct.Scale = 0, ct.Level() = 0, ct.IsNTT() != true
func (eval *evaluator) RescaleNew(ct0 *Ciphertext, threshold float64) (ctOut *Ciphertext, err error) {

	ctOut = NewCiphertext(eval.params, ct0.Degree(), ct0.Level(), ct0.Scale)

	return ctOut, eval.Rescale(ct0, threshold, ctOut)
}

// Rescale divides ct0 by the last modulus in the moduli chain, and repeats this
// procedure (consuming one level each time) until the scale reaches the original scale or before it goes below it, and returns the result
// in ctOut. Since all the moduli in the moduli chain are generated to be close to the
// original scale, this procedure is equivalent to dividing the input element by the scale and adding
// some error.
// Returns an error if "minScale <= 0", ct.Scale = 0, ct.Level() = 0, ct.IsNTT() != true or if ct.Leve() != ctOut.Level()
func (eval *evaluator) Rescale(ctIn *Ciphertext, minScale float64, ctOut *Ciphertext) (err error) {

	ringQ := eval.params.RingQ()

	if minScale <= 0 {
		return errors.New("cannot Rescale: minScale is 0")
	}

	if ctIn.Scale == 0 {
		return errors.New("cannot Rescale: ciphertext scale is 0")
	}

	if ctIn.Level() == 0 {
		return errors.New("cannot Rescale: input Ciphertext already at level 0")
	}

	if ctOut.Degree() != ctIn.Degree() {
		return errors.New("cannot Rescale : ctIn.Degree() != ctOut.Degree()")
	}

	ctOut.Scale = ctIn.Scale

	var nbRescales int
	// Divides the scale by each moduli of the modulus chain as long as the scale isn't smaller than minScale/2
	// or until the output Level() would be zero
	for ctOut.Scale/float64(ringQ.Modulus[ctIn.Level()-nbRescales]) >= minScale/2 && ctIn.Level()-nbRescales >= 0 {
		ctOut.Scale /= (float64(ringQ.Modulus[ctIn.Level()-nbRescales]))
		nbRescales++
	}

	if nbRescales > 0 {
		level := ctIn.Level()
		for i := range ctOut.Value {
			ringQ.DivRoundByLastModulusManyNTTLvl(level, nbRescales, ctIn.Value[i], eval.poolQMul[0], ctOut.Value[i])
			ctOut.Value[i].Coeffs = ctOut.Value[i].Coeffs[:level+1-nbRescales]
		}
	} else {
		if ctIn != ctOut {
			ctOut.Copy(ctIn)
		}
	}

	return nil
}

// MulNew multiplies op0 with op1 without relinearization and returns the result in a newly created element.
// The procedure will panic if either op0.Degree or op1.Degree > 1.
func (eval *evaluator) MulNew(op0, op1 Operand) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, op0.Degree()+op1.Degree(), utils.MinInt(op0.Level(), op1.Level()), 0)
	eval.mulRelin(op0, op1, false, ctOut)
	return
}

// Mul multiplies op0 with op1 without relinearization and returns the result in ctOut.
// The procedure will panic if either op0 or op1 are have a degree higher than 1.
// The procedure will panic if ctOut.Degree != op0.Degree + op1.Degree.
func (eval *evaluator) Mul(op0, op1 Operand, ctOut *Ciphertext) {
	eval.mulRelin(op0, op1, false, ctOut)
}

// MulRelinNew multiplies ct0 by ct1 with relinearization and returns the result in a newly created element.
// The procedure will panic if either op0.Degree or op1.Degree > 1.
// The procedure will panic if the evaluator was not created with an relinearization key.
func (eval *evaluator) MulRelinNew(op0, op1 Operand) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, 1, utils.MinInt(op0.Level(), op1.Level()), 0)
	eval.mulRelin(op0, op1, true, ctOut)
	return
}

// MulRelin multiplies op0 with op1 with relinearization and returns the result in ctOut.
// The procedure will panic if either op0.Degree or op1.Degree > 1.
// The procedure will panic if ctOut.Degree != op0.Degree + op1.Degree.
// The procedure will panic if the evaluator was not created with an relinearization key.
func (eval *evaluator) MulRelin(op0, op1 Operand, ctOut *Ciphertext) {
	eval.mulRelin(op0, op1, true, ctOut)
}

func (eval *evaluator) mulRelin(op0, op1 Operand, relin bool, ctOut *Ciphertext) {

	eval.checkBinary(op0, op1, ctOut, utils.MaxInt(op0.Degree(), op1.Degree()))

	level := utils.MinInt(utils.MinInt(op0.Level(), op1.Level()), ctOut.Level())

	if ctOut.Level() > level {
		eval.DropLevel(ctOut, ctOut.Level()-level)
	}

	if op0.Degree() > 1 || op1.Degree() > 1 {
		panic("cannot MulRelin: input elements must be of degree 0 or 1")
	}

	ctOut.Scale = op0.ScalingFactor() * op1.ScalingFactor()

	ringQ := eval.params.RingQ()

	var c00, c01, c0, c1, c2 *ring.Poly

	// Case Ciphertext (x) Ciphertext
	if op0.Degree()+op1.Degree() == 2 {

		c00 = eval.poolQMul[0]
		c01 = eval.poolQMul[1]

		c0 = ctOut.Value[0]
		c1 = ctOut.Value[1]

		if !relin {
			if ctOut.Degree() < 2 {
				ctOut.El().Resize(eval.params.Parameters, 2)
			}
			c2 = ctOut.Value[2]
		} else {
			c2 = eval.poolQMul[2]
		}

		// Avoid overwriting if the second input is the output
		var tmp0, tmp1 *rlwe.Ciphertext
		if op1.El() == ctOut.El() {
			tmp0, tmp1 = op1.El(), op0.El()
		} else {
			tmp0, tmp1 = op0.El(), op1.El()
		}

		ringQ.MFormLvl(level, tmp0.Value[0], c00)
		ringQ.MFormLvl(level, tmp0.Value[1], c01)

		if op0 == op1 { // squaring case
			ringQ.MulCoeffsMontgomeryLvl(level, c00, tmp1.Value[0], c0) // c0 = c[0]*c[0]
			ringQ.MulCoeffsMontgomeryLvl(level, c01, tmp1.Value[1], c2) // c2 = c[1]*c[1]
			ringQ.MulCoeffsMontgomeryLvl(level, c00, tmp1.Value[1], c1) // c1 = 2*c[0]*c[1]
			ringQ.AddLvl(level, c1, c1, c1)

		} else { // regular case
			ringQ.MulCoeffsMontgomeryLvl(level, c00, tmp1.Value[0], c0) // c0 = c0[0]*c0[0]
			ringQ.MulCoeffsMontgomeryLvl(level, c01, tmp1.Value[1], c2) // c2 = c0[1]*c1[1]
			ringQ.MulCoeffsMontgomeryLvl(level, c00, tmp1.Value[1], c1)
			ringQ.MulCoeffsMontgomeryAndAddLvl(level, c01, tmp1.Value[0], c1) // c1 = c0[0]*c1[1] + c0[1]*c1[0]
		}

		if relin {
			c2.IsNTT = false
			eval.RingQ().InvNTTLvl(level, c2, c2)
			eval.SwitchKeysInPlace(level, c2, eval.rlk.Keys[0], eval.Pool[1].Q, eval.Pool[2].Q)

			ringQ.NTTLazyLvl(level, eval.Pool[1].Q, eval.Pool[1].Q)
			ringQ.NTTLazyLvl(level, eval.Pool[2].Q, eval.Pool[2].Q)

			ringQ.AddLvl(level, c0, eval.Pool[1].Q, ctOut.Value[0])
			ringQ.AddLvl(level, c1, eval.Pool[2].Q, ctOut.Value[1])
		}

		// Case Plaintext (x) Ciphertext or Ciphertext (x) Plaintext
	} else {

		var tmp0, tmp1 *rlwe.Ciphertext

		if op0.Degree() == 1 {
			tmp0, tmp1 = op1.El(), op0.El()
		} else {
			tmp0, tmp1 = op0.El(), op1.El()
		}

		c00 := eval.poolQMul[0]

		ringQ.MFormLvl(level, tmp0.Value[0], c00)
		ringQ.MulCoeffsMontgomeryLvl(level, c00, tmp1.Value[0], ctOut.Value[0])
		ringQ.MulCoeffsMontgomeryLvl(level, c00, tmp1.Value[1], ctOut.Value[1])
	}
}

// MulAndAdd multiplies op0 with op1 without relinearization and adds the result on ctOut.
// User must ensure that ctOut.Scale <= op0.Scale * op1.Scale.
// If ctOut.Scale < op0.Scale * op1.Scale, then scales up ctOut before adding the result.
// The procedure will panic if either op0 or op1 are have a degree higher than 1.
// The procedure will panic if ctOut.Degree != op0.Degree + op1.Degree.
func (eval *evaluator) MulAndAdd(op0, op1 Operand, ctOut *Ciphertext) {
	eval.mulRelinAndAdd(op0, op1, false, ctOut)
}

// MulRelinAndAdd multiplies op0 with op1 with relinearization and adds the result on ctOut.
// User must ensure that ctOut.Scale <= op0.Scale * op1.Scale.
// If ctOut.Scale < op0.Scale * op1.Scale, then scales up ctOut before adding the result.
// The procedure will panic if either op0.Degree or op1.Degree > 1.
// The procedure will panic if ctOut.Degree != op0.Degree + op1.Degree.
// The procedure will panic if the evaluator was not created with an relinearization key.
func (eval *evaluator) MulRelinAndAdd(op0, op1 Operand, ctOut *Ciphertext) {
	eval.mulRelinAndAdd(op0, op1, true, ctOut)
}

func (eval *evaluator) mulRelinAndAdd(op0, op1 Operand, relin bool, ctOut *Ciphertext) {

	eval.checkBinary(op0, op1, ctOut, utils.MaxInt(op0.Degree(), op1.Degree()))

	level := utils.MinInt(utils.MinInt(op0.Level(), op1.Level()), ctOut.Level())

	if ctOut.Level() > level {
		eval.DropLevel(ctOut, ctOut.Level()-level)
	}

	if op0.Degree() > 1 || op1.Degree() > 1 {
		panic("cannot MulRelinAndAdd: input elements must be of degree 0 or 1")
	}

	resScale := op0.ScalingFactor() * op1.ScalingFactor()

	if ctOut.Scale < resScale {
		eval.MultByConst(ctOut, math.Round(resScale/ctOut.Scale), ctOut)
		ctOut.Scale = resScale
	}

	ringQ := eval.params.RingQ()

	var c00, c01, c0, c1, c2 *ring.Poly

	// Case Ciphertext (x) Ciphertext
	if op0.Degree()+op1.Degree() == 2 {

		c00 = eval.poolQMul[0]
		c01 = eval.poolQMul[1]

		c0 = ctOut.Value[0]
		c1 = ctOut.Value[1]

		if !relin {
			if ctOut.Degree() < 2 {
				ctOut.El().Resize(eval.params.Parameters, 2)
			}
			c2 = ctOut.Value[2]
		} else {
			c2 = eval.poolQMul[2]
		}

		// Avoid overwriting if the second input is the output
		var tmp0, tmp1 *rlwe.Ciphertext
		if op1.El() == ctOut.El() {
			tmp0, tmp1 = op1.El(), op0.El()
		} else {
			tmp0, tmp1 = op0.El(), op1.El()
		}

		ringQ.MFormLvl(level, tmp0.Value[0], c00)
		ringQ.MFormLvl(level, tmp0.Value[1], c01)

		ringQ.MulCoeffsMontgomeryAndAddLvl(level, c00, tmp1.Value[0], c0) // c0 = c[0]*c[0]
		ringQ.MulCoeffsMontgomeryAndAddLvl(level, c00, tmp1.Value[1], c1) // c1 = c[0]*c[1]
		ringQ.MulCoeffsMontgomeryAndAddLvl(level, c00, tmp1.Value[1], c1) // c1 = c[0]*c[1]

		if relin {
			c2.IsNTT = true
			ringQ.MulCoeffsMontgomeryLvl(level, c01, tmp1.Value[1], c2) // c2 = c[1]*c[1]
			eval.SwitchKeysInPlace(level, c2, eval.rlk.Keys[0], eval.Pool[1].Q, eval.Pool[2].Q)
			ringQ.AddLvl(level, c0, eval.Pool[1].Q, c0)
			ringQ.AddLvl(level, c1, eval.Pool[2].Q, c1)
		} else {
			ringQ.MulCoeffsMontgomeryAndAddLvl(level, c01, tmp1.Value[1], c2) // c2 = c[1]*c[1]
		}

		// Case Plaintext (x) Ciphertext or Ciphertext (x) Plaintext
	} else {

		var tmp0, tmp1 *rlwe.Ciphertext

		if op0.Degree() == 1 {
			tmp0, tmp1 = op1.El(), op0.El()
		} else {
			tmp0, tmp1 = op0.El(), op1.El()
		}

		c00 := eval.poolQMul[0]

		ringQ.MFormLvl(level, tmp0.Value[0], c00)
		ringQ.MulCoeffsMontgomeryAndAddLvl(level, c00, tmp1.Value[0], ctOut.Value[0])
		ringQ.MulCoeffsMontgomeryAndAddLvl(level, c00, tmp1.Value[1], ctOut.Value[1])
	}
}

// RelinearizeNew applies the relinearization procedure on ct0 and returns the result in a newly
// created Ciphertext. The input Ciphertext must be of degree two.
func (eval *evaluator) RelinearizeNew(ct0 *Ciphertext) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, 1, ct0.Level(), ct0.Scale)
	eval.Relinearize(ct0, ctOut)
	return
}

// Relinearize applies the relinearization procedure on ct0 and returns the result in ctOut. The input Ciphertext must be of degree two.
func (eval *evaluator) Relinearize(ct0 *Ciphertext, ctOut *Ciphertext) {
	if ct0.Degree() != 2 {
		panic("cannot Relinearize: input Ciphertext is not of degree 2")
	}

	if ctOut.Level() > ct0.Level() {
		eval.DropLevel(ctOut, ctOut.Level()-ct0.Level())
	}

	ctOut.Scale = ct0.Scale

	level := utils.MinInt(ct0.Level(), ctOut.Level())
	ringQ := eval.params.RingQ()

	eval.SwitchKeysInPlace(level, ct0.Value[2], eval.rlk.Keys[0], eval.Pool[1].Q, eval.Pool[2].Q)

	ringQ.AddLvl(level, ct0.Value[0], eval.Pool[1].Q, ctOut.Value[0])
	ringQ.AddLvl(level, ct0.Value[1], eval.Pool[2].Q, ctOut.Value[1])

	ctOut.El().Resize(eval.params.Parameters, 1)
}

// SwitchKeysNew re-encrypts ct0 under a different key and returns the result in a newly created element.
// It requires a SwitchingKey, which is computed from the key under which the Ciphertext is currently encrypted,
// and the key under which the Ciphertext will be re-encrypted.
func (eval *evaluator) SwitchKeysNew(ct0 *Ciphertext, switchingKey *rlwe.SwitchingKey) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, ct0.Degree(), ct0.Level(), ct0.Scale)
	eval.SwitchKeys(ct0, switchingKey, ctOut)
	return
}

// SwitchKeys re-encrypts ct0 under a different key and returns the result in ctOut.
// It requires a SwitchingKey, which is computed from the key under which the Ciphertext is currently encrypted,
// and the key under which the Ciphertext will be re-encrypted.
func (eval *evaluator) SwitchKeys(ct0 *Ciphertext, switchingKey *rlwe.SwitchingKey, ctOut *Ciphertext) {

	if ct0.Degree() != 1 || ctOut.Degree() != 1 {
		panic("cannot SwitchKeys: input and output Ciphertext must be of degree 1")
	}

	level := utils.MinInt(ct0.Level(), ctOut.Level())
	ringQ := eval.params.RingQ()

	ctOut.Scale = ct0.Scale

	eval.SwitchKeysInPlace(level, ct0.Value[1], switchingKey, eval.Pool[1].Q, eval.Pool[2].Q)

	ringQ.AddLvl(level, ct0.Value[0], eval.Pool[1].Q, ctOut.Value[0])
	ring.CopyValuesLvl(level, eval.Pool[2].Q, ctOut.Value[1])
}

// RotateNew rotates the columns of ct0 by k positions to the left, and returns the result in a newly created element.
// If the provided element is a Ciphertext, a key-switching operation is necessary and a rotation key for the specific rotation needs to be provided.
func (eval *evaluator) RotateNew(ct0 *Ciphertext, k int) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, ct0.Degree(), ct0.Level(), ct0.Scale)
	eval.Rotate(ct0, k, ctOut)
	return
}

// Rotate rotates the columns of ct0 by k positions to the left and returns the result in ctOut.
// If the provided element is a Ciphertext, a key-switching operation is necessary and a rotation key for the specific rotation needs to be provided.
func (eval *evaluator) Rotate(ct0 *Ciphertext, k int, ctOut *Ciphertext) {

	if ct0.Degree() != 1 || ctOut.Degree() != 1 {
		panic("cannot Rotate: input and output Ciphertext must be of degree 1")
	}

	if k == 0 {
		ctOut.Copy(ct0)
	} else {

		ctOut.Scale = ct0.Scale

		galEl := eval.params.GaloisElementForColumnRotationBy(k)

		eval.permuteNTT(ct0, galEl, ctOut)
	}
}

// ConjugateNew conjugates ct0 (which is equivalent to a row rotation) and returns the result in a newly
// created element. If the provided element is a Ciphertext, a key-switching operation is necessary and a rotation key
// for the row rotation needs to be provided.
func (eval *evaluator) ConjugateNew(ct0 *Ciphertext) (ctOut *Ciphertext) {

	if eval.params.RingType() == ring.ConjugateInvariant {
		panic("method ConjugateNew is not supported when params.RingType() == ring.ConjugateInvariant")
	}

	ctOut = NewCiphertext(eval.params, ct0.Degree(), ct0.Level(), ct0.Scale)
	eval.Conjugate(ct0, ctOut)
	return
}

// Conjugate conjugates ct0 (which is equivalent to a row rotation) and returns the result in ctOut.
// If the provided element is a Ciphertext, a key-switching operation is necessary and a rotation key for the row rotation needs to be provided.
func (eval *evaluator) Conjugate(ct0 *Ciphertext, ctOut *Ciphertext) {

	if eval.params.RingType() == ring.ConjugateInvariant {
		panic("method Conjugate is not supported when params.RingType() == ring.ConjugateInvariant")
	}

	if ct0.Degree() != 1 || ctOut.Degree() != 1 {
		panic("input and output Ciphertext must be of degree 1")
	}

	galEl := eval.params.GaloisElementForRowRotation()
	ctOut.Scale = ct0.Scale
	eval.permuteNTT(ct0, galEl, ctOut)
}

func (eval *evaluator) permuteNTT(ct0 *Ciphertext, galEl uint64, ctOut *Ciphertext) {

	rtk, generated := eval.rtks.GetRotationKey(galEl)
	if !generated {
		panic(fmt.Sprintf("rotation key k=%d not available", eval.params.InverseGaloisElement(galEl)))
	}

	level := utils.MinInt(ct0.Level(), ctOut.Level())
	pool2Q := eval.Pool[1].Q
	pool3Q := eval.Pool[2].Q
	ringQ := eval.params.RingQ()

	ringQ.InvNTTLvl(level, ct0.Value[1], pool2Q)
	pool2Q.IsNTT = false
	eval.SwitchKeysInPlace(level, pool2Q, rtk, ctOut.Value[0], ctOut.Value[1])

	ringQ.NTTLvl(level, ctOut.Value[0], pool2Q)
	ringQ.NTTLvl(level, ctOut.Value[1], pool3Q)

	ringQ.AddLvl(level, pool2Q, ct0.Value[0], pool2Q)

	ringQ.PermuteNTTLvl(level, pool2Q, galEl, ctOut.Value[0])
	ringQ.PermuteNTTLvl(level, pool3Q, galEl, ctOut.Value[1])
}

func (eval *evaluator) RotateHoistedNoModDownNew(level int, rotations []int, c0 *ring.Poly, c2DecompQP []rlwe.PolyQP) (cOut map[int][2]rlwe.PolyQP) {
	ringQ := eval.params.RingQ()
	ringP := eval.params.RingP()
	cOut = make(map[int][2]rlwe.PolyQP)
	for _, i := range rotations {

		if i != 0 {
			cOut[i] = [2]rlwe.PolyQP{{Q: ringQ.NewPolyLvl(level), P: ringP.NewPoly()}, {Q: ringQ.NewPolyLvl(level), P: ringP.NewPoly()}}
			eval.PermuteNTTHoistedNoModDown(level, c0, c2DecompQP, i, cOut[i][0].Q, cOut[i][1].Q, cOut[i][0].P, cOut[i][1].P)
		}
	}

	return
}

func (eval *evaluator) PermuteNTTHoistedNoModDown(level int, c0 *ring.Poly, c2DecompQP []rlwe.PolyQP, k int, ct0OutQ, ct1OutQ, ct0OutP, ct1OutP *ring.Poly) {

	pool2Q := eval.Pool[0].Q
	pool3Q := eval.Pool[1].Q

	pool2P := eval.Pool[0].P
	pool3P := eval.Pool[1].P

	levelQ := level
	levelP := eval.params.PCount() - 1

	galEl := eval.params.GaloisElementForColumnRotationBy(k)

	rtk, generated := eval.rtks.Keys[galEl]
	if !generated {
		fmt.Println(k)
		panic("switching key not available")
	}
	index := eval.permuteNTTIndex[galEl]

	eval.KeyswitchHoistedNoModDown(levelQ, c2DecompQP, rtk, pool2Q, pool3Q, pool2P, pool3P)

	ringQ := eval.params.RingQ()

	ringQ.PermuteNTTWithIndexLvl(levelQ, pool3Q, index, ct1OutQ)
	ringQ.PermuteNTTWithIndexLvl(levelP, pool3P, index, ct1OutP)

	ringQ.MulScalarBigintLvl(levelQ, c0, eval.params.RingP().ModulusBigint, pool3Q)
	ringQ.AddLvl(levelQ, pool2Q, pool3Q, pool2Q)

	ringQ.PermuteNTTWithIndexLvl(levelQ, pool2Q, index, ct0OutQ)
	ringQ.PermuteNTTWithIndexLvl(levelP, pool2P, index, ct0OutP)
}

func (eval *evaluator) PermuteNTTHoisted(level int, c0, c1 *ring.Poly, c2DecompQP []rlwe.PolyQP, k int, cOut0, cOut1 *ring.Poly) {

	if k == 0 {
		cOut0.Copy(c0)
		cOut1.Copy(c1)
		return
	}

	galEl := eval.params.GaloisElementForColumnRotationBy(k)
	rtk, generated := eval.rtks.Keys[galEl]
	if !generated {
		panic(fmt.Sprintf("specific rotation has not been generated: %d", k))
	}

	index := eval.permuteNTTIndex[galEl]

	pool2Q := eval.Pool[0].Q
	pool3Q := eval.Pool[1].Q

	pool2P := eval.Pool[0].P
	pool3P := eval.Pool[1].P

	eval.KeyswitchHoisted(level, c2DecompQP, rtk, pool2Q, pool3Q, pool2P, pool3P)

	ringQ := eval.params.RingQ()

	ringQ.AddLvl(level, pool2Q, c0, pool2Q)

	ringQ.PermuteNTTWithIndexLvl(level, pool2Q, index, cOut0)
	ringQ.PermuteNTTWithIndexLvl(level, pool3Q, index, cOut1)
}
