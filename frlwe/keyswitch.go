package frlwe

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"math/big"
)

type KeySwitcher struct {
	params Parameters

	gadgetVec []rlwe.PolyQP

	polyRPools1 []*ring.Poly
	polyRPools2 []*ring.Poly

	polyQPPool1 rlwe.PolyQP
	polyQPPool2 rlwe.PolyQP

	polyRHalfR  *ring.Poly
	polyQPHalfR rlwe.PolyQP

	convQP *ring.BasisExtender
	convRP *ring.BasisExtender
	convRQ *ring.BasisExtender
}

func NewKeySwitcher(params Parameters) *KeySwitcher {
	ksw := new(KeySwitcher)
	ksw.params = params
	ksw.gadgetVec = make([]rlwe.PolyQP, params.Alpha()+params.Beta())
	ksw.polyRPools1 = make([]*ring.Poly, params.Alpha()+params.Beta())
	ksw.polyRPools2 = make([]*ring.Poly, params.Alpha()+params.Beta())

	ksw.polyQPPool1 = params.RingQP().NewPoly()
	ksw.polyQPPool2 = params.RingQP().NewPoly()

	ringQ := params.RingQ()
	ringP := params.RingP()
	ringQP := params.RingQP()
	ringR := params.RingR()

	ksw.polyQPHalfR = ringQP.NewPoly()
	ksw.polyRHalfR = ringR.NewPoly()
	halfR := big.NewInt(0).Div(ringR.ModulusBigint, big.NewInt(2))

	ringR.AddScalarBigint(ksw.polyRHalfR, halfR, ksw.polyRHalfR)
	ringQ.AddScalarBigint(ksw.polyQPHalfR.Q, halfR, ksw.polyQPHalfR.Q)
	ringP.AddScalarBigint(ksw.polyQPHalfR.P, halfR, ksw.polyQPHalfR.P)

	for i := 0; i < len(ksw.polyRPools1); i++ {
		ksw.polyRPools1[i] = ringR.NewPoly()
	}

	for i := 0; i < len(ksw.polyRPools2); i++ {
		ksw.polyRPools2[i] = ringR.NewPoly()
	}

	ksw.convQP = ring.NewBasisExtender(ringQ, ringP)
	ksw.convRP = ring.NewBasisExtender(ringR, ringP)
	ksw.convRQ = ring.NewBasisExtender(ringR, ringQ)

	for i := 0; i < len(ksw.gadgetVec); i++ {
		ksw.gadgetVec[i] = ringQP.NewPoly()
	}

	//generate gadget vector
	bigIntQP := big.NewInt(1).Mul(params.RingQ().ModulusBigint, params.RingP().ModulusBigint)
	alpha := params.Alpha()
	beta := params.Beta()

	for i := 0; i < beta; i++ {
		qi := big.NewInt(int64(params.RingQ().Modulus[i]))
		gi := big.NewInt(0).Div(bigIntQP, qi)
		qiHat := big.NewInt(0).ModInverse(gi, qi)
		gi.Mul(gi, qiHat)
		ringQ.AddScalarBigint(ksw.gadgetVec[i].Q, gi, ksw.gadgetVec[i].Q)
		ringQ.MForm(ksw.gadgetVec[i].Q, ksw.gadgetVec[i].Q)
		ringP.AddScalarBigint(ksw.gadgetVec[i].P, gi, ksw.gadgetVec[i].P)
		ringP.MForm(ksw.gadgetVec[i].P, ksw.gadgetVec[i].P)
	}

	for i := beta; i < beta+alpha; i++ {
		pi := big.NewInt(int64(params.RingP().Modulus[i-beta]))
		gi := big.NewInt(0).Div(bigIntQP, pi)
		piHat := big.NewInt(0).ModInverse(gi, pi)
		gi.Mul(gi, piHat)
		ringQ.AddScalarBigint(ksw.gadgetVec[i].Q, gi, ksw.gadgetVec[i].Q)
		ringQ.MForm(ksw.gadgetVec[i].Q, ksw.gadgetVec[i].Q)
		ringP.AddScalarBigint(ksw.gadgetVec[i].P, gi, ksw.gadgetVec[i].P)
		ringP.MForm(ksw.gadgetVec[i].P, ksw.gadgetVec[i].P)
	}

	return ksw
}

//assume input a and output c is in InvNTT form
func (ksw *KeySwitcher) InternalProduct(levelQ int, a *ring.Poly, bg *SwitchingKey, c *ring.Poly) {

	params := ksw.params
	ringQP := params.RingQP()
	ringR := params.RingR()

	alpha := params.Alpha()
	beta := params.Beta()

	levelP := params.PCount() - 1
	levelR := len(ringR.Modulus) - 1

	if a.IsNTT {
		panic("a should not be in NTT")
	}

	for i := 0; i < levelQ+1; i++ {
		ringR.SetCoefficientsUint64(a.Coeffs[i], ksw.polyRPools1[i])
		ringR.NTTLazy(ksw.polyRPools1[i], ksw.polyRPools1[i])
	}

	//set polyRPools2 to zero
	for i := 0; i < levelQ+1; i++ {
		ksw.polyRPools2[i].Zero()
	}

	for i := 0; i < alpha; i++ {
		ksw.polyRPools2[i+beta].Zero()
	}

	//product and sum up coeffs
	for i := 0; i < levelQ+1; i++ {
		for j := 0; j < levelQ+1; j++ {
			ringR.MulCoeffsMontgomeryAndAdd(ksw.polyRPools1[i], bg.Value[i][j], ksw.polyRPools2[j])
		}

		for j := 0; j < alpha; j++ {
			ringR.MulCoeffsMontgomeryAndAdd(ksw.polyRPools1[i], bg.Value[i][j+beta], ksw.polyRPools2[j+beta])
		}
	}

	for i := 0; i < levelQ+1; i++ {
		ringR.InvNTTLazy(ksw.polyRPools2[i], ksw.polyRPools2[i])
	}

	for i := 0; i < alpha; i++ {
		ringR.InvNTTLazy(ksw.polyRPools2[i+beta], ksw.polyRPools2[i+beta])
	}

	//move coeffs to ringQP
	ksw.polyQPPool2.Q.Zero()
	ksw.polyQPPool2.P.Zero()

	for i := 0; i < levelQ+1; i++ {
		ringR.Add(ksw.polyRPools2[i], ksw.polyRHalfR, ksw.polyRPools2[i])
		ksw.convRQ.ModUpQtoP(levelR, levelQ, ksw.polyRPools2[i], ksw.polyQPPool1.Q)
		ksw.convRP.ModUpQtoP(levelR, levelP, ksw.polyRPools2[i], ksw.polyQPPool1.P)

		ringQP.SubLvl(levelQ, levelP, ksw.polyQPPool1, ksw.polyQPHalfR, ksw.polyQPPool1)

		ringQP.MulCoeffsMontgomeryLvl(levelQ, levelP, ksw.polyQPPool1, ksw.gadgetVec[i], ksw.polyQPPool1)

		ringQP.AddLvl(levelQ, levelP, ksw.polyQPPool1, ksw.polyQPPool2, ksw.polyQPPool2)
	}

	for i := beta; i < beta+alpha; i++ {
		ringR.Add(ksw.polyRPools2[i], ksw.polyRHalfR, ksw.polyRPools2[i])
		ksw.convRQ.ModUpQtoP(levelR, levelQ, ksw.polyRPools2[i], ksw.polyQPPool1.Q)
		ksw.convRP.ModUpQtoP(levelR, levelP, ksw.polyRPools2[i], ksw.polyQPPool1.P)

		ringQP.SubLvl(levelQ, levelP, ksw.polyQPPool1, ksw.polyQPHalfR, ksw.polyQPPool1)

		ringQP.MulCoeffsMontgomeryLvl(levelQ, levelP, ksw.polyQPPool1, ksw.gadgetVec[i], ksw.polyQPPool1)

		ringQP.AddLvl(levelQ, levelP, ksw.polyQPPool1, ksw.polyQPPool2, ksw.polyQPPool2)
	}

	//Div by P
	ksw.convQP.ModDownQPtoQ(levelQ, levelP, ksw.polyQPPool2.Q, ksw.polyQPPool2.P, c)

	return
}
