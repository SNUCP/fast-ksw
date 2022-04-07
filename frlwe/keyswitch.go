package frlwe

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"math/big"
)

type KeySwitcher struct {
	params Parameters

	halfRPolyQP rlwe.PolyQP
	halfRPolyR  *ring.Poly

	polyRPools1 []*ring.Poly
	polyRPools2 []*ring.Poly

	polyQPPool rlwe.PolyQP

	polyQPool *ring.Poly

	convQP  *ring.BasisExtender
	convRP  *ring.BasisExtender
	convRQi []*ring.BasisExtender

	ringQi []*ring.Ring
}

func NewKeySwitcher(params Parameters) *KeySwitcher {
	ksw := new(KeySwitcher)
	ksw.params = params
	ksw.polyRPools1 = make([]*ring.Poly, params.Alpha()+params.Beta())
	ksw.polyRPools2 = make([]*ring.Poly, params.Alpha()+params.Beta())

	ksw.polyQPPool = params.RingQP().NewPoly()
	ksw.polyQPool = params.RingQ().NewPoly()

	ringQ := params.RingQ()
	ringP := params.RingP()
	ringQP := params.RingQP()
	ringR := params.RingR()

	beta := params.Beta()

	//generate ringQi
	ksw.ringQi = make([]*ring.Ring, beta)
	for i := 0; i < beta; i++ {
		ksw.ringQi[i], _ = ring.NewRing(params.N(), []uint64{ringQ.Modulus[i]})
	}

	halfR := big.NewInt(0).Div(ringR.ModulusBigint, big.NewInt(2))
	ksw.halfRPolyQP = ringQP.NewPoly()
	ringQ.AddScalarBigint(ksw.halfRPolyQP.Q, halfR, ksw.halfRPolyQP.Q)
	ringP.AddScalarBigint(ksw.halfRPolyQP.P, halfR, ksw.halfRPolyQP.P)

	ksw.halfRPolyR = ringR.NewPoly()
	ringR.AddScalarBigint(ksw.halfRPolyR, halfR, ksw.halfRPolyR)

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

	return ksw
}

//assume input a and output c is in InvNTT form
func (ksw *KeySwitcher) externalProduct(levelQ int, aPolyRs []*ring.Poly, bg *SwitchingKey, c *ring.Poly) {

	params := ksw.params
	ringQP := params.RingQP()
	ringR := params.RingR()

	alpha := params.Alpha()
	beta := params.Beta()

	levelP := params.PCount() - 1
	levelR := len(ringR.Modulus) - 1

	//product and sum up coeffs
	RiOverFlow := params.RiOverflowMargin(levelR) >> 1
	reduce := 0

	for i := 0; i < levelQ+1; i++ {
		for j := 0; j < levelQ+1; j++ {
			if i == 0 {
				ringR.MulCoeffsMontgomeryConstant(aPolyRs[i], bg.Value[i][j], ksw.polyRPools2[j])
			} else {
				ringR.MulCoeffsMontgomeryConstantAndAddNoMod(aPolyRs[i], bg.Value[i][j], ksw.polyRPools2[j])
			}

			if reduce%RiOverFlow == RiOverFlow-1 {
				ringR.Reduce(ksw.polyRPools2[j], ksw.polyRPools2[j])
			}
		}

		for j := 0; j < alpha; j++ {
			if i == 0 {
				ringR.MulCoeffsMontgomeryConstant(aPolyRs[i], bg.Value[i][j+beta], ksw.polyRPools2[j+beta])
			} else {
				ringR.MulCoeffsMontgomeryConstantAndAddNoMod(aPolyRs[i], bg.Value[i][j+beta], ksw.polyRPools2[j+beta])
			}

			if reduce%RiOverFlow == RiOverFlow-1 {
				ringR.Reduce(ksw.polyRPools2[j+beta], ksw.polyRPools2[j+beta])
			}
		}

		reduce++
	}

	if reduce%RiOverFlow != 0 {
		for i := 0; i < levelQ+1; i++ {
			ringR.Reduce(ksw.polyRPools2[i], ksw.polyRPools2[i])
		}
		for i := 0; i < alpha; i++ {
			ringR.Reduce(ksw.polyRPools2[i+beta], ksw.polyRPools2[i+beta])
		}
	}

	// apply invNTT
	for i := 0; i < levelQ+1; i++ {
		ringR.InvNTTLazy(ksw.polyRPools2[i], ksw.polyRPools2[i])
	}

	for i := 0; i < alpha; i++ {
		ringR.InvNTTLazy(ksw.polyRPools2[i+beta], ksw.polyRPools2[i+beta])
	}

	//move coeffs to ringQP
	for i := 0; i < levelQ+1; i++ {
		ringR.AddNoMod(ksw.polyRPools2[i], ksw.halfRPolyR, ksw.polyRPools2[i])
		ksw.convRQi[i].ModUpQtoP(levelR, 0, ksw.polyRPools2[i], ksw.polyQPool)

		copy(ksw.polyQPPool.Q.Coeffs[i], ksw.polyQPool.Coeffs[0])
	}

	for i := beta; i < beta+alpha; i++ {
		ringR.AddNoMod(ksw.polyRPools2[i], ksw.halfRPolyR, ksw.polyRPools2[i])
		ksw.convRP.ModUpQtoP(levelR, 0, ksw.polyRPools2[i], ksw.polyQPool)

		copy(ksw.polyQPPool.P.Coeffs[i-beta], ksw.polyQPool.Coeffs[0])
	}

	ringQP.SubLvl(levelQ, levelP, ksw.polyQPPool, ksw.halfRPolyQP, ksw.polyQPPool)

	//Div by P
	ksw.convQP.ModDownQPtoQ(levelQ, levelP, ksw.polyQPPool.Q, ksw.polyQPPool.P, c)

	return
}

func (ksw *KeySwitcher) SwitchKey(levelQ int, a *ring.Poly, bg0, bg1 *SwitchingKey, c0, c1 *ring.Poly) {

	params := ksw.params
	ringR := params.RingR()
	levelR := len(ringR.Modulus) - 1

	if a.IsNTT {
		panic("a should not be in NTT")
	}

	for i := 0; i < levelQ+1; i++ {
		for j := 0; j < levelR+1; j++ {
			ringR.NTTSingleLazy(j, a.Coeffs[i], ksw.polyRPools1[i].Coeffs[j])
		}
	}

	ksw.externalProduct(levelQ, ksw.polyRPools1, bg0, c0)
	ksw.externalProduct(levelQ, ksw.polyRPools1, bg1, c1)

	return
}
