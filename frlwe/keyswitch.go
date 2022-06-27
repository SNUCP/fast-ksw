package frlwe

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"math"
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
	convRPi []*ring.BasisExtender
	convRQi []*ring.BasisExtender

	convQjR []*ring.BasisExtender
	convPR  *ring.BasisExtender

	ringQi []*ring.Ring
	ringQj []*ring.Ring
	ringPi []*ring.Ring
}

func NewKeySwitcher(params Parameters) *KeySwitcher {
	ksw := new(KeySwitcher)
	ksw.params = params

	alpha := params.Alpha()
	beta := params.Beta()
	gamma := params.Gamma()
	level := params.MaxLevel()

	blockLenQi := int(math.Ceil(float64(level+1) / float64(gamma)))
	blockLenPi := int(math.Ceil(float64(alpha) / float64(gamma)))

	ksw.polyRPools1 = make([]*ring.Poly, beta)
	ksw.polyRPools2 = make([]*ring.Poly, blockLenQi+blockLenPi)

	ksw.polyQPPool = params.RingQP().NewPoly()
	ksw.polyQPool = params.RingQ().NewPoly()

	ringQ := params.RingQ()
	ringP := params.RingP()
	ringQP := params.RingQP()
	ringR := params.RingR()

	ksw.convQP = ring.NewBasisExtender(ringQ, ringP)

	// generate ringQi
	ksw.ringQi = make([]*ring.Ring, blockLenQi)
	for i := 0; i < blockLenQi; i++ {
		modulusQi := make([]uint64, 0)
		for j := 0; j < gamma; j++ {
			if i*gamma+j < level+1 {
				modulusQi = append(modulusQi, ringQ.Modulus[i*gamma+j])
			}
		}

		ksw.ringQi[i], _ = ring.NewRing(params.N(), modulusQi)
	}

	// generate convRQi
	ksw.convRQi = make([]*ring.BasisExtender, blockLenQi)
	for i := 0; i < blockLenQi; i++ {
		ksw.convRQi[i] = ring.NewBasisExtender(ringR, ksw.ringQi[i])
	}

	// generate ringPi
	ksw.ringPi = make([]*ring.Ring, blockLenPi)
	for i := 0; i < blockLenPi; i++ {
		modulusPi := make([]uint64, 0)
		for j := 0; j < gamma; j++ {
			if i*gamma+j < alpha {
				modulusPi = append(modulusPi, ringP.Modulus[i*gamma+j])
			}
		}

		ksw.ringPi[i], _ = ring.NewRing(params.N(), modulusPi)
	}

	// generate convRPi
	ksw.convRPi = make([]*ring.BasisExtender, blockLenPi)
	for i := 0; i < blockLenPi; i++ {
		ksw.convRPi[i] = ring.NewBasisExtender(ringR, ksw.ringPi[i])
	}

	// generate precomputable constants
	halfR := big.NewInt(0).Div(ringR.ModulusBigint, big.NewInt(2))
	ksw.halfRPolyQP = ringQP.NewPoly()
	ringQ.AddScalarBigint(ksw.halfRPolyQP.Q, halfR, ksw.halfRPolyQP.Q)
	ringP.AddScalarBigint(ksw.halfRPolyQP.P, halfR, ksw.halfRPolyQP.P)

	ksw.halfRPolyR = ringR.NewPoly()
	ringR.AddScalarBigint(ksw.halfRPolyR, halfR, ksw.halfRPolyR)

	// generate poly pools
	for i := 0; i < len(ksw.polyRPools1); i++ {
		ksw.polyRPools1[i] = ringR.NewPoly()
	}

	for i := 0; i < len(ksw.polyRPools2); i++ {
		ksw.polyRPools2[i] = ringR.NewPoly()
	}

	// generate convPR
	ksw.convPR = ring.NewBasisExtender(ringP, ringR)

	// generate ringQj
	ksw.ringQj = make([]*ring.Ring, beta)
	for i := 0; i < beta; i++ {
		modulusQj := make([]uint64, 0)
		for j := 0; j < alpha; j++ {
			if i*alpha+j < level+1 {
				modulusQj = append(modulusQj, ringQ.Modulus[i*alpha+j])
			}
		}

		ksw.ringQj[i], _ = ring.NewRing(params.N(), modulusQj)
	}

	// generate convQjR
	ksw.convQjR = make([]*ring.BasisExtender, beta)
	for i := 0; i < beta; i++ {
		ksw.convQjR[i] = ring.NewBasisExtender(ksw.ringQj[i], ringR)
	}

	return ksw
}

//assume input a and output c is in InvNTT form
func (ksw *KeySwitcher) externalProduct(levelQ int, aPolyRs []*ring.Poly, bg *SwitchingKey, c *ring.Poly) {

	params := ksw.params
	ringQP := params.RingQP()
	ringR := params.RingR()

	alpha := params.Alpha()
	beta := int(math.Ceil(float64(levelQ+1) / float64(alpha)))
	gamma := params.Gamma()

	levelP := params.PCount() - 1
	levelR := len(ringR.Modulus) - 1

	blockLenQi := int(math.Ceil(float64(levelQ+1) / float64(gamma)))
	maxBlockLenQi := int(math.Ceil(float64(params.MaxLevel()+1) / float64(gamma)))
	blockLenPi := int(math.Ceil(float64(alpha) / float64(gamma)))

	//product and sum up coeffs
	RiOverFlow := params.RiOverflowMargin(levelR) >> 1
	reduce := 0

	for i := 0; i < beta; i++ {
		for j := 0; j < blockLenQi; j++ {
			if i == 0 {
				ringR.MulCoeffsMontgomeryConstant(aPolyRs[i], bg.Value[i][j], ksw.polyRPools2[j])
			} else {
				ringR.MulCoeffsMontgomeryConstantAndAddNoMod(aPolyRs[i], bg.Value[i][j], ksw.polyRPools2[j])
			}

			if reduce%RiOverFlow == RiOverFlow-1 {
				ringR.Reduce(ksw.polyRPools2[j], ksw.polyRPools2[j])
			}
		}

		for j := maxBlockLenQi; j < maxBlockLenQi+blockLenPi; j++ {
			if i == 0 {
				ringR.MulCoeffsMontgomeryConstant(aPolyRs[i], bg.Value[i][j], ksw.polyRPools2[j])
			} else {
				ringR.MulCoeffsMontgomeryConstantAndAddNoMod(aPolyRs[i], bg.Value[i][j], ksw.polyRPools2[j])
			}

			if reduce%RiOverFlow == RiOverFlow-1 {
				ringR.Reduce(ksw.polyRPools2[j], ksw.polyRPools2[j])
			}
		}

		reduce++
	}

	if reduce%RiOverFlow != 0 {
		for i := 0; i < blockLenQi; i++ {
			ringR.Reduce(ksw.polyRPools2[i], ksw.polyRPools2[i])
		}

		for i := maxBlockLenQi; i < maxBlockLenQi+blockLenPi; i++ {
			ringR.Reduce(ksw.polyRPools2[i], ksw.polyRPools2[i])
		}
	}

	// apply invNTT
	for i := 0; i < blockLenQi; i++ {
		ringR.InvNTTLazy(ksw.polyRPools2[i], ksw.polyRPools2[i])
	}

	for i := maxBlockLenQi; i < maxBlockLenQi+blockLenPi; i++ {
		ringR.InvNTTLazy(ksw.polyRPools2[i], ksw.polyRPools2[i])
	}

	//move coeffs to ringQP
	for i := 0; i < blockLenQi; i++ {
		levelQi := -1
		for j := 0; j < gamma; j++ {
			if i*gamma+j < levelQ+1 {
				levelQi += 1
			}
		}

		ringR.AddNoMod(ksw.polyRPools2[i], ksw.halfRPolyR, ksw.polyRPools2[i])
		ksw.convRQi[i].ModUpQtoP(levelR, levelQi, ksw.polyRPools2[i], ksw.polyQPool)

		for j := 0; j < levelQi+1; j++ {
			copy(ksw.polyQPPool.Q.Coeffs[i*gamma+j], ksw.polyQPool.Coeffs[j])
		}
	}

	for i := 0; i < blockLenPi; i++ {
		levelPi := -1
		for j := 0; j < gamma; j++ {
			if i*gamma+j < alpha {
				levelPi += 1
			}
		}

		ringR.AddNoMod(ksw.polyRPools2[i+maxBlockLenQi], ksw.halfRPolyR, ksw.polyRPools2[i+maxBlockLenQi])
		ksw.convRPi[i].ModUpQtoP(levelR, levelPi, ksw.polyRPools2[i+maxBlockLenQi], ksw.polyQPool)

		for j := 0; j < levelPi+1; j++ {
			copy(ksw.polyQPPool.P.Coeffs[i*gamma+j], ksw.polyQPool.Coeffs[j])
		}
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

	alpha := params.Alpha()
	beta := int(math.Ceil(float64(levelQ+1) / float64(alpha)))

	for i := 0; i < beta; i++ {
		levelQj := -1
		for j := 0; j < alpha; j++ {
			if i*alpha+j < levelQ+1 {
				levelQj++
				copy(ksw.polyQPool.Coeffs[j], a.Coeffs[i*alpha+j])
			}
		}

		ksw.convQjR[i].ModUpQtoP(levelQj, levelR, ksw.polyQPool, ksw.polyRPools1[i])
		ringR.NTT(ksw.polyRPools1[i], ksw.polyRPools1[i])
	}

	ksw.externalProduct(levelQ, ksw.polyRPools1, bg0, c0)
	ksw.externalProduct(levelQ, ksw.polyRPools1, bg1, c1)

	return
}
