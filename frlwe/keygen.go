package frlwe

import (
	"fast-ksw/ring"
	"fast-ksw/rlwe"

	"math"
)

type KeyGenerator struct {
	rlwe.KeyGenerator
	params Parameters

	ringRi     []*ring.Ring
	convRiT    []*ring.BasisExtender
	polyRiPool *ring.Poly
}

func NewKeyGenerator(params Parameters) (keygen *KeyGenerator) {
	keygen = new(KeyGenerator)
	keygen.KeyGenerator = rlwe.NewKeyGenerator(params.Parameters)
	keygen.params = params

	level := params.MaxLevel()
	alpha := params.Alpha()
	gamma := params.Gamma()

	blockLen := int(math.Ceil(float64(level+alpha+1) / float64(gamma)))

	keygen.ringRi = make([]*ring.Ring, blockLen)
	keygen.convRiT = make([]*ring.BasisExtender, blockLen)

	ringR := params.RingR()

	for i := 0; i < blockLen; i++ {
		modulusRi := make([]uint64, 0)
		for j := 0; j < gamma; j++ {
			if i*gamma+j < level+alpha+1 {
				modulusRi = append(modulusRi, ringR.Modulus[i*gamma+j])
			}
		}

		keygen.ringRi[i], _ = ring.NewRing(params.N(), modulusRi)
		keygen.convRiT[i] = ring.NewBasisExtender(keygen.ringRi[i], params.RingT())
	}
	keygen.polyRiPool = params.RingR().NewPolyLvl(gamma - 1)

	return
}

func (keygen *KeyGenerator) GenSecretKey() *rlwe.SecretKey {
	return keygen.GenSecretKey()
}

func (keygen *KeyGenerator) GenPublicKey(sk *rlwe.SecretKey) *rlwe.PublicKey {
	return keygen.GenPublicKey(sk)
}

func (keygen *KeyGenerator) polyQPToPolyTs(polyQP rlwe.PolyQP, polyTs []*ring.Poly) {

	params := keygen.params

	level := params.MaxLevel()
	alpha := params.Alpha()
	gamma := params.Gamma()

	ringT := params.RingT()
	levelT := len(ringT.Modulus) - 1

	coeffsQ := polyQP.Q.GetCoefficients()
	coeffsP := polyQP.P.GetCoefficients()
	blockLen := int(math.Ceil(float64(level+alpha+1) / float64(gamma)))

	for i := 0; i < blockLen; i++ {
		levelRi := -1
		for j := 0; j < gamma; j++ {
			if i*gamma+j < alpha {
				levelRi++
				copy(keygen.polyRiPool.Coeffs[j], coeffsP[i*gamma+j])
			} else if i*gamma+j < level+alpha+1 {
				levelRi++
				copy(keygen.polyRiPool.Coeffs[j], coeffsQ[i*gamma+j-alpha])
			}
		}
		keygen.convRiT[i].ModUpQtoP(levelRi, levelT, keygen.polyRiPool, polyTs[i])

		ringT.NTT(polyTs[i], polyTs[i])
		ringT.MForm(polyTs[i], polyTs[i])
	}

}

func (keygen *KeyGenerator) GenRelinKey(sk *rlwe.SecretKey) (rlk *RelinKey) {

	params := keygen.params
	ringQP := params.RingQP()
	rlk = NewRelinKey(params)
	rlweRlk := keygen.GenRelinearizationKey(sk, 1).Keys[0]

	beta := params.Beta()
	alpha := params.Alpha()

	levelQ := params.MaxLevel()
	levelP := alpha - 1

	for i := 0; i < beta; i++ {
		ringQP.InvMFormLvl(levelQ, levelP, rlweRlk.Value[i][0], rlweRlk.Value[i][0])
		ringQP.InvNTTLvl(levelQ, levelP, rlweRlk.Value[i][0], rlweRlk.Value[i][0])
		keygen.polyQPToPolyTs(rlweRlk.Value[i][0], rlk.Value[0].Value[i])

		ringQP.InvMFormLvl(levelQ, levelP, rlweRlk.Value[i][1], rlweRlk.Value[i][1])
		ringQP.InvNTTLvl(levelQ, levelP, rlweRlk.Value[i][1], rlweRlk.Value[i][1])
		keygen.polyQPToPolyTs(rlweRlk.Value[i][1], rlk.Value[1].Value[i])
	}

	return
}
