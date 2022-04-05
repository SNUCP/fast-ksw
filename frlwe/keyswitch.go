package frlwe

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"math/big"
)

type KeySwitcher struct {
	params Parameters

	gadgetVec []rlwe.PolyQP
	halfR     *big.Int

	polyRPools1 []*ring.Poly
	polyRPools2 []*ring.Poly

	polyQPPool1 rlwe.PolyQP
	polyQPPool2 rlwe.PolyQP

	polyQPool *ring.Poly

	convQP  *ring.BasisExtender
	convRP  *ring.BasisExtender
	convRQi []*ring.BasisExtender

	ringQi []*ring.Ring
}

func NewKeySwitcher(params Parameters) *KeySwitcher {
	ksw := new(KeySwitcher)
	ksw.params = params
	ksw.gadgetVec = make([]rlwe.PolyQP, params.Alpha()+params.Beta())
	ksw.polyRPools1 = make([]*ring.Poly, params.Alpha()+params.Beta())
	ksw.polyRPools2 = make([]*ring.Poly, params.Alpha()+params.Beta())

	ksw.polyQPPool1 = params.RingQP().NewPoly()
	ksw.polyQPPool2 = params.RingQP().NewPoly()

	ksw.polyQPool = params.RingQ().NewPoly()

	ringQ := params.RingQ()
	ringP := params.RingP()
	ringQP := params.RingQP()
	ringR := params.RingR()

	alpha := params.Alpha()
	beta := params.Beta()

	//generate ringQi
	ksw.ringQi = make([]*ring.Ring, beta)
	for i := 0; i < beta; i++ {
		ksw.ringQi[i], _ = ring.NewRing(params.N(), []uint64{ringQ.Modulus[i]})
	}

	ksw.halfR = big.NewInt(0).Div(ringR.ModulusBigint, big.NewInt(2))

	for i := 0; i < len(ksw.polyRPools1); i++ {
		ksw.polyRPools1[i] = ringR.NewPoly()
	}

	for i := 0; i < len(ksw.polyRPools2); i++ {
		ksw.polyRPools2[i] = ringR.NewPoly()
	}

	ksw.convQP = ring.NewBasisExtender(ringQ, ringP)
	ksw.convRP = ring.NewBasisExtender(ringR, ringP)

	ksw.convRQi = make([]*ring.BasisExtender, beta)
	for i := 0; i < beta; i++ {
		ksw.convRQi[i] = ring.NewBasisExtender(ringR, ksw.ringQi[i])
	}

	for i := 0; i < len(ksw.gadgetVec); i++ {
		ksw.gadgetVec[i] = ringQP.NewPoly()
	}

	//generate gadget vector
	bigIntQP := big.NewInt(1).Mul(params.RingQ().ModulusBigint, params.RingP().ModulusBigint)

	for i := 0; i < beta; i++ {
		qi := big.NewInt(int64(params.RingQ().Modulus[i]))
		gi := big.NewInt(0).Div(bigIntQP, qi)
		qiHat := big.NewInt(0).ModInverse(gi, qi)
		gi.Mul(gi, qiHat)
		ringQ.AddScalarBigint(ksw.gadgetVec[i].Q, gi, ksw.gadgetVec[i].Q)
		ringP.AddScalarBigint(ksw.gadgetVec[i].P, gi, ksw.gadgetVec[i].P)

		ringQP.MFormLvl(beta-1, alpha-1, ksw.gadgetVec[i], ksw.gadgetVec[i])
	}

	for i := beta; i < beta+alpha; i++ {
		pi := big.NewInt(int64(params.RingP().Modulus[i-beta]))
		gi := big.NewInt(0).Div(bigIntQP, pi)
		piHat := big.NewInt(0).ModInverse(gi, pi)
		gi.Mul(gi, piHat)
		ringQ.AddScalarBigint(ksw.gadgetVec[i].Q, gi, ksw.gadgetVec[i].Q)
		ringP.AddScalarBigint(ksw.gadgetVec[i].P, gi, ksw.gadgetVec[i].P)

		ringQP.MFormLvl(beta-1, alpha-1, ksw.gadgetVec[i], ksw.gadgetVec[i])
	}

	return ksw
}

//assume input a and output c is in InvNTT form
func (ksw *KeySwitcher) InternalProduct(levelQ int, a *ring.Poly, bg *SwitchingKey, c *ring.Poly) {

	params := ksw.params
	ringQP := params.RingQP()
	ringQ := params.RingQ()
	ringP := params.RingP()
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
		ringR.AddScalarBigint(ksw.polyRPools2[i], ksw.halfR, ksw.polyRPools2[i])
		ksw.convRQi[i].ModUpQtoP(levelR, 0, ksw.polyRPools2[i], ksw.polyQPool)
		ksw.ringQi[i].SubScalarBigintLvl(0, ksw.polyQPool, ksw.halfR, ksw.polyQPool)

		ringQ.MulByVectorMontgomeryLvl(levelQ, ksw.gadgetVec[i].Q, ksw.polyQPool.Coeffs[0], ksw.polyQPPool1.Q)
		ringP.MulByVectorMontgomeryLvl(levelP, ksw.gadgetVec[i].P, ksw.polyQPool.Coeffs[0], ksw.polyQPPool1.P)

		ringQP.AddLvl(levelQ, levelP, ksw.polyQPPool1, ksw.polyQPPool2, ksw.polyQPPool2)
	}

	for i := beta; i < beta+alpha; i++ {
		ringR.AddScalarBigint(ksw.polyRPools2[i], ksw.halfR, ksw.polyRPools2[i])
		ksw.convRP.ModUpQtoP(levelR, 0, ksw.polyRPools2[i], ksw.polyQPool)
		ringP.SubScalarBigintLvl(0, ksw.polyQPool, ksw.halfR, ksw.polyQPool)

		ringQ.MulByVectorMontgomeryLvl(levelQ, ksw.gadgetVec[i].Q, ksw.polyQPool.Coeffs[0], ksw.polyQPPool1.Q)
		ringP.MulByVectorMontgomeryLvl(levelP, ksw.gadgetVec[i].P, ksw.polyQPool.Coeffs[0], ksw.polyQPPool1.P)

		ringQP.AddLvl(levelQ, levelP, ksw.polyQPPool1, ksw.polyQPPool2, ksw.polyQPPool2)
	}

	//Div by P
	ksw.convQP.ModDownQPtoQ(levelQ, levelP, ksw.polyQPPool2.Q, ksw.polyQPPool2.P, c)

	return
}
