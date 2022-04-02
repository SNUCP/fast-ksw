package frlwe

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"math/big"
)

type KeySwitcher struct {
	params      Parameters
	gadgetVec   []*big.Int
	polyQPPool  rlwe.PolyQP
	polyRPools1 []*ring.Poly
	polyRPools2 []*ring.Poly

	polyQPool *ring.Poly
	polyPPool *ring.Poly

	convQP *ring.BasisExtender
	convRP *ring.BasisExtender
	convRQ *ring.BasisExtender
}

func NewKeySwitcher(params Parameters) *KeySwitcher {
	ksw := new(KeySwitcher)
	ksw.params = params
	ksw.gadgetVec = make([]*big.Int, params.Alpha()+params.Beta())
	ksw.polyQPPool = params.RingQP().NewPoly()
	ksw.polyRPools1 = make([]*ring.Poly, params.Alpha()+params.Beta())
	ksw.polyRPools2 = make([]*ring.Poly, params.Alpha()+params.Beta())
	ksw.polyQPool = params.RingQ().NewPoly()
	ksw.polyPPool = params.RingP().NewPoly()

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

	bigIntQP := big.NewInt(1)
	bigIntQP.Mul(params.QBigInt(), params.PBigInt())

	//generate gadget vector

	for i := 0; i < params.Beta(); i++ {
		qi := big.NewInt(int64(params.RingQ().Modulus[i]))
		qiHat := big.NewInt(0)
		qiHatInv := big.NewInt(0)
		gi := big.NewInt(0)

		qiHat.Div(bigIntQP, qi)
		qiHatInv.ModInverse(qiHat, qi)
		gi.Mul(qiHat, qiHatInv)
		ksw.gadgetVec[i].Set(gi)
	}

	for i := 0; i < params.Alpha(); i++ {
		pi := big.NewInt(int64(params.RingP().Modulus[i]))
		piHat := big.NewInt(0)
		piHatInv := big.NewInt(0)
		gi := big.NewInt(0)

		piHat.Div(bigIntQP, pi)
		piHatInv.ModInverse(piHat, pi)
		gi.Mul(piHat, piHatInv)
		ksw.gadgetVec[i+params.Beta()].Set(gi)
	}

	return ksw
}

//assume input a and output c is in InvNTT form
func (ksw *KeySwitcher) InternalProduct(levelQ int, a *ring.Poly, bg *SwitchingKey, c *ring.Poly) {

	params := ksw.params
	ringQ := params.RingQ()
	ringP := params.RingP()
	ringR := params.RingR()

	if a.IsNTT {
		panic("a should not be in NTT")
	}

	gadgetDim := levelQ + 1

	//move coeffs of a into ringR
	aCoeffs := a.GetCoefficients()

	for i := 0; i < gadgetDim; i++ {
		ringR.SetCoefficientsUint64(aCoeffs[i], ksw.polyRPools1[i])
		ringR.NTT(ksw.polyRPools1[i], ksw.polyRPools1[i])
	}

	//set polyRPools2 to zero
	for i := 0; i < gadgetDim; i++ {
		ksw.polyRPools2[i].Zero()
	}

	//product and sum up coeffs
	for i := 0; i < params.Alpha(); i++ {
		ksw.polyRPools2[i+params.Beta()].Zero()
	}

	for i := 0; i < gadgetDim; i++ {
		for j := 0; j < gadgetDim; j++ {
			ringR.MulCoeffsMontgomeryAndAdd(ksw.polyRPools1[i], bg.Value[i][j], ksw.polyRPools2[j])
		}

		for j := 0; j < params.Alpha(); j++ {
			ringR.MulCoeffsMontgomeryAndAdd(ksw.polyRPools1[i], bg.Value[i][j+params.Beta()], ksw.polyRPools2[j+params.Beta()])
		}
	}

	for i := 0; i < gadgetDim; i++ {
		ringR.InvNTT(ksw.polyRPools2[i], ksw.polyRPools2[i])
	}

	for i := 0; i < params.Alpha(); i++ {
		ringR.InvNTT(ksw.polyRPools2[i+params.Beta()], ksw.polyRPools2[i+params.Beta()])
	}

	//move coeffs to ringQP
	ksw.polyQPPool.Q.Zero()
	ksw.polyQPPool.P.Zero()

	levelR := len(ringR.Modulus) - 1
	levelP := params.PCount() - 1

	for i := 0; i < gadgetDim; i++ {
		ksw.convRQ.ModUpQtoP(levelR, levelQ, ksw.polyRPools2[i], ksw.polyQPool)
		ksw.convRP.ModUpQtoP(levelR, levelP, ksw.polyRPools2[i], ksw.polyPPool)
		ringQ.MulScalarBigintLvl(levelQ, ksw.polyQPool, ksw.gadgetVec[i], ksw.polyQPool)
		ringQ.AddLvl(levelQ, ksw.polyQPool, ksw.polyQPPool.Q, ksw.polyQPPool.Q)

		ringP.MulScalarBigintLvl(levelP, ksw.polyPPool, ksw.gadgetVec[i], ksw.polyPPool)
		ringP.AddLvl(levelP, ksw.polyPPool, ksw.polyQPPool.P, ksw.polyQPPool.P)
	}

	for i := params.Beta(); i < params.Beta()+params.Alpha(); i++ {
		ksw.convRQ.ModUpQtoP(levelR, levelQ, ksw.polyRPools2[i], ksw.polyQPool)
		ksw.convRP.ModUpQtoP(levelR, levelP, ksw.polyRPools2[i], ksw.polyPPool)
		ringQ.MulScalarBigintLvl(levelQ, ksw.polyQPool, ksw.gadgetVec[i], ksw.polyQPool)
		ringQ.AddLvl(levelQ, ksw.polyQPool, ksw.polyQPPool.Q, ksw.polyQPPool.Q)

		ringP.MulScalarBigintLvl(levelP, ksw.polyPPool, ksw.gadgetVec[i], ksw.polyPPool)
		ringP.AddLvl(levelP, ksw.polyPPool, ksw.polyQPPool.P, ksw.polyQPPool.P)
	}

	//Div by P
	ksw.convQP.ModDownQPtoQ(levelQ, levelP, ksw.polyQPPool.Q, ksw.polyQPPool.P, c)

	return
}
