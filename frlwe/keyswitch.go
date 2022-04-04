package frlwe

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"math/big"
)

type KeySwitcher struct {
	params      Parameters
	gadgetVec   []*big.Int
	polyRPools1 []*ring.Poly
	polyRPools2 []*ring.Poly

	polyQPPool1 rlwe.PolyQP
	polyQPPool2 rlwe.PolyQP

	bigIntPool []*big.Int

	convQP *ring.BasisExtender
	convRP *ring.BasisExtender
	convRQ *ring.BasisExtender
}

func NewKeySwitcher(params Parameters) *KeySwitcher {
	ksw := new(KeySwitcher)
	ksw.params = params
	ksw.gadgetVec = make([]*big.Int, params.Alpha()+params.Beta())
	ksw.polyRPools1 = make([]*ring.Poly, params.Alpha()+params.Beta())
	ksw.polyRPools2 = make([]*ring.Poly, params.Alpha()+params.Beta())

	ksw.polyQPPool1 = params.RingQP().NewPoly()
	ksw.polyQPPool2 = params.RingQP().NewPoly()

	ksw.bigIntPool = make([]*big.Int, params.N())

	for i := 0; i < len(ksw.polyRPools1); i++ {
		ksw.polyRPools1[i] = params.RingR().NewPoly()
	}

	for i := 0; i < len(ksw.polyRPools2); i++ {
		ksw.polyRPools2[i] = params.RingR().NewPoly()
	}

	ksw.convQP = ring.NewBasisExtender(params.RingQ(), params.RingP())
	ksw.convRP = ring.NewBasisExtender(params.RingR(), params.RingP())
	ksw.convRQ = ring.NewBasisExtender(params.RingR(), params.RingQ())

	for i := 0; i < len(ksw.gadgetVec); i++ {
		ksw.gadgetVec[i] = big.NewInt(0)
	}

	for i := 0; i < params.N(); i++ {
		ksw.bigIntPool[i] = big.NewInt(0)
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
		ksw.gadgetVec[i].Set(gi)
	}

	for i := beta; i < beta+alpha; i++ {
		pi := big.NewInt(int64(params.RingP().Modulus[i-beta]))
		gi := big.NewInt(0).Div(bigIntQP, pi)
		piHat := big.NewInt(0).ModInverse(gi, pi)
		gi.Mul(gi, piHat)
		ksw.gadgetVec[i].Set(gi)
	}

	return ksw
}

//assume input a and output c is in InvNTT form
func (ksw *KeySwitcher) InternalProduct(levelQ int, a *ring.Poly, bg *SwitchingKey, c *ring.Poly) {

	params := ksw.params
	ringQ := params.RingQ()
	ringP := params.RingP()
	ringQP := params.RingQP()
	ringR := params.RingR()

	alpha := params.Alpha()
	beta := params.Beta()

	levelP := params.PCount() - 1
	levelR := len(ringR.Modulus) - 1

	halfR := big.NewInt(0).Div(ringR.ModulusBigint, big.NewInt(2))

	if a.IsNTT {
		panic("a should not be in NTT")
	}

	//move coeffs of a into ringR
	aCoeffs := a.GetCoefficients()

	for i := 0; i < levelQ+1; i++ {
		ringR.SetCoefficientsUint64(aCoeffs[i], ksw.polyRPools1[i])
		ringR.NTT(ksw.polyRPools1[i], ksw.polyRPools1[i])
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
		ringR.InvNTT(ksw.polyRPools2[i], ksw.polyRPools2[i])
	}

	for i := 0; i < alpha; i++ {
		ringR.InvNTT(ksw.polyRPools2[i+beta], ksw.polyRPools2[i+beta])
	}

	//move coeffs to ringQP
	ksw.polyQPPool2.Q.Zero()
	ksw.polyQPPool2.P.Zero()

	for i := 0; i < levelQ+1; i++ {
		ringR.AddScalarBigint(ksw.polyRPools2[i], halfR, ksw.polyRPools2[i])
		ksw.convRQ.ModUpQtoP(levelR, levelQ, ksw.polyRPools2[i], ksw.polyQPPool1.Q)
		ksw.convRP.ModUpQtoP(levelR, levelP, ksw.polyRPools2[i], ksw.polyQPPool1.P)

		ringQ.SubScalarBigintLvl(levelQ, ksw.polyQPPool1.Q, halfR, ksw.polyQPPool1.Q)
		ringQ.MulScalarBigintLvl(levelQ, ksw.polyQPPool1.Q, ksw.gadgetVec[i], ksw.polyQPPool1.Q)

		ringP.SubScalarBigintLvl(levelP, ksw.polyQPPool1.P, halfR, ksw.polyQPPool1.P)
		ringP.MulScalarBigintLvl(levelP, ksw.polyQPPool1.P, ksw.gadgetVec[i], ksw.polyQPPool1.P)

		ringQP.AddLvl(levelQ, levelP, ksw.polyQPPool1, ksw.polyQPPool2, ksw.polyQPPool2)
	}

	for i := beta; i < beta+alpha; i++ {
		ringR.AddScalarBigint(ksw.polyRPools2[i], halfR, ksw.polyRPools2[i])
		ksw.convRQ.ModUpQtoP(levelR, levelQ, ksw.polyRPools2[i], ksw.polyQPPool1.Q)
		ksw.convRP.ModUpQtoP(levelR, levelP, ksw.polyRPools2[i], ksw.polyQPPool1.P)

		ringQ.SubScalarBigintLvl(levelQ, ksw.polyQPPool1.Q, halfR, ksw.polyQPPool1.Q)
		ringQ.MulScalarBigintLvl(levelQ, ksw.polyQPPool1.Q, ksw.gadgetVec[i], ksw.polyQPPool1.Q)

		ringP.SubScalarBigintLvl(levelP, ksw.polyQPPool1.P, halfR, ksw.polyQPPool1.P)
		ringP.MulScalarBigintLvl(levelP, ksw.polyQPPool1.P, ksw.gadgetVec[i], ksw.polyQPPool1.P)

		ringQP.AddLvl(levelQ, levelP, ksw.polyQPPool1, ksw.polyQPPool2, ksw.polyQPPool2)
	}

	//Div by P
	ksw.convQP.ModDownQPtoQ(levelQ, levelP, ksw.polyQPPool2.Q, ksw.polyQPPool2.P, c)

	return
}
