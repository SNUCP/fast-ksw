package frlwe

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"math"
	"math/big"
)

type KeySwitcher struct {
	params Parameters

	halfTPolyQP rlwe.PolyQP
	halfTPolyT  *ring.Poly

	polyTPools1 []*ring.Poly
	polyTPools2 []*ring.Poly

	polyQPPool rlwe.PolyQP
	polyQPool  *ring.Poly
	polyTPool  *ring.Poly
	polyRPool  *ring.Poly

	convQP  *ring.BasisExtender
	convTRi []*ring.BasisExtender
	convQjT []*ring.BasisExtender

	ringRi []*ring.Ring
	ringQj []*ring.Ring
}

func NewKeySwitcher(params Parameters) *KeySwitcher {
	ksw := new(KeySwitcher)
	ksw.params = params

	alpha := params.Alpha()
	beta := params.Beta()
	gamma := params.Gamma()
	level := params.MaxLevel()

	blockLen := int(math.Ceil(float64(level+alpha+1) / float64(gamma)))

	ksw.polyQPPool = params.RingQP().NewPoly()
	ksw.polyQPool = params.RingQ().NewPoly()
	ksw.polyRPool = params.RingR().NewPoly()
	ksw.polyTPool = params.RingT().NewPoly()

	ringQ := params.RingQ()
	ringP := params.RingP()
	ringQP := params.RingQP()
	ringR := params.RingR()
	ringT := params.RingT()

	ksw.convQP = ring.NewBasisExtender(ringQ, ringP)

	// generate ringRi convTRi
	ksw.ringRi = make([]*ring.Ring, blockLen)
	ksw.convTRi = make([]*ring.BasisExtender, blockLen)

	for i := 0; i < blockLen; i++ {
		modulusRi := make([]uint64, 0)
		for j := 0; j < gamma; j++ {
			if i*gamma+j < level+alpha+1 {
				modulusRi = append(modulusRi, ringR.Modulus[i*gamma+j])
			}
		}

		ksw.ringRi[i], _ = ring.NewRing(params.N(), modulusRi)
		ksw.convTRi[i] = ring.NewBasisExtender(params.RingT(), ksw.ringRi[i])
	}

	// generate ringQj convQjT
	ksw.ringQj = make([]*ring.Ring, beta)
	ksw.convQjT = make([]*ring.BasisExtender, beta)

	for j := 0; j < beta; j++ {
		modulusQj := make([]uint64, 0)
		for i := 0; i < alpha; i++ {
			if j*alpha+i < level+1 {
				modulusQj = append(modulusQj, ringQ.Modulus[j*alpha+i])
			}
		}

		ksw.ringQj[j], _ = ring.NewRing(params.N(), modulusQj)
		ksw.convQjT[j] = ring.NewBasisExtender(ksw.ringQj[j], params.RingT())
	}

	// generate precomputable constants
	halfT := big.NewInt(0).Div(ringT.ModulusBigint, big.NewInt(2))
	ksw.halfTPolyQP = ringQP.NewPoly()
	ringQ.AddScalarBigint(ksw.halfTPolyQP.Q, halfT, ksw.halfTPolyQP.Q)
	ringP.AddScalarBigint(ksw.halfTPolyQP.P, halfT, ksw.halfTPolyQP.P)

	ksw.halfTPolyT = ringT.NewPoly()
	ringT.AddScalarBigint(ksw.halfTPolyT, halfT, ksw.halfTPolyT)

	// generate poly pools
	ksw.polyTPools1 = make([]*ring.Poly, beta)
	ksw.polyTPools2 = make([]*ring.Poly, blockLen)

	for i := 0; i < len(ksw.polyTPools1); i++ {
		ksw.polyTPools1[i] = ringT.NewPoly()
	}

	for i := 0; i < len(ksw.polyTPools2); i++ {
		ksw.polyTPools2[i] = ringT.NewPoly()
	}

	return ksw
}

//assume input a and output c is in InvNTT form
func (ksw *KeySwitcher) externalProduct(levelQ int, aPolyTs []*ring.Poly, bg *SwitchingKey, c *ring.Poly) {

	params := ksw.params
	ringQP := params.RingQP()
	ringT := params.RingT()

	alpha := params.Alpha()
	beta := int(math.Ceil(float64(levelQ+1) / float64(alpha)))
	gamma := params.Gamma()

	levelT := len(ringT.Modulus) - 1
	levelP := alpha - 1
	blockLen := int(math.Ceil(float64(levelQ+alpha+1) / float64(gamma)))

	//product and sum up coeffs
	TiOverFlow := params.TiOverflowMargin(levelT) >> 1
	reduce := 0

	for i := 0; i < beta; i++ {
		for j := 0; j < blockLen; j++ {
			if i == 0 {
				ringT.MulCoeffsMontgomeryConstant(aPolyTs[i], bg.Value[i][j], ksw.polyTPools2[j])
			} else {
				ringT.MulCoeffsMontgomeryConstantAndAddNoMod(aPolyTs[i], bg.Value[i][j], ksw.polyTPools2[j])
			}

			if reduce%TiOverFlow == TiOverFlow-1 {
				ringT.Reduce(ksw.polyTPools2[j], ksw.polyTPools2[j])
			}
		}

		reduce++
	}

	if reduce%TiOverFlow != 0 {
		for i := 0; i < blockLen; i++ {
			ringT.Reduce(ksw.polyTPools2[i], ksw.polyTPools2[i])
		}
	}

	// apply invNTT
	for i := 0; i < blockLen; i++ {
		ringT.InvNTTLazy(ksw.polyTPools2[i], ksw.polyTPools2[i])
	}

	//move coeffs to ringQP
	for i := 0; i < blockLen; i++ {
		levelRi := -1
		for j := 0; j < gamma; j++ {
			if i*gamma+j < levelQ+alpha+1 {
				levelRi++
			}
		}

		ringT.AddNoMod(ksw.polyTPools2[i], ksw.halfTPolyT, ksw.polyTPools2[i])
		ksw.convTRi[i].ModUpQtoP(levelT, levelRi, ksw.polyTPools2[i], ksw.polyRPool)

		for j := 0; j < levelRi+1; j++ {
			if i*gamma+j < alpha {
				copy(ksw.polyQPPool.P.Coeffs[i*gamma+j], ksw.polyRPool.Coeffs[j])
			} else {
				copy(ksw.polyQPPool.Q.Coeffs[i*gamma+j-alpha], ksw.polyRPool.Coeffs[j])
			}
		}
	}

	ringQP.SubLvl(levelQ, levelP, ksw.polyQPPool, ksw.halfTPolyQP, ksw.polyQPPool)

	//Div by P
	ksw.convQP.ModDownQPtoQ(levelQ, levelP, ksw.polyQPPool.Q, ksw.polyQPPool.P, c)

	return
}

func (ksw *KeySwitcher) SwitchKey(levelQ int, a *ring.Poly, bg0, bg1 *SwitchingKey, c0, c1 *ring.Poly) {

	params := ksw.params
	ringT := params.RingT()
	levelT := len(ringT.Modulus) - 1

	if a.IsNTT {
		panic("a should not be in NTT")
	}

	alpha := params.Alpha()
	beta := int(math.Ceil(float64(levelQ+1) / float64(alpha)))

	for j := 0; j < beta; j++ {
		levelQj := -1
		for i := 0; i < alpha; i++ {
			if j*alpha+i < levelQ+1 {
				levelQj++
				copy(ksw.polyQPool.Coeffs[j], a.Coeffs[i*alpha+j])
			}
		}

		ksw.convQjT[j].ModUpQtoP(levelQj, levelT, ksw.polyQPool, ksw.polyTPools1[j])
		ringT.NTTLazy(ksw.polyTPools1[j], ksw.polyTPools1[j])
	}

	ksw.externalProduct(levelQ, ksw.polyTPools1, bg0, c0)
	ksw.externalProduct(levelQ, ksw.polyTPools1, bg1, c1)

	return
}
