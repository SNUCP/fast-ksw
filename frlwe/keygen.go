package frlwe

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

type KeyGenerator struct {
	rlwe.KeyGenerator
	params Parameters

	ringQi  []*ring.Ring
	convQiR []*ring.BasisExtender
	convPR  *ring.BasisExtender

	polyQPool *ring.Poly
}

func NewKeyGenerator(params Parameters) (keygen *KeyGenerator) {
	keygen = new(KeyGenerator)
	keygen.KeyGenerator = rlwe.NewKeyGenerator(params.Parameters)
	keygen.params = params

	keygen.ringQi = make([]*ring.Ring, params.Beta()/params.Gamma())
	keygen.convQiR = make([]*ring.BasisExtender, params.Beta()/params.Gamma())

	beta := params.Beta()
	gamma := params.Gamma()

	ringQ := params.RingQ()

	for i := 0; i < beta/gamma; i++ {
		modulusQi := make([]uint64, 0)
		for j := 0; j < gamma; j++ {
			modulusQi = append(modulusQi, ringQ.Modulus[i*gamma+j])
		}

		keygen.ringQi[i], _ = ring.NewRing(params.N(), modulusQi)
		keygen.convQiR[i] = ring.NewBasisExtender(keygen.ringQi[i], params.RingR())
	}
	keygen.convPR = ring.NewBasisExtender(params.RingP(), params.RingR())

	keygen.polyQPool = params.RingQ().NewPolyLvl(gamma - 1)

	return
}

func (keygen *KeyGenerator) GenSecretKey() *rlwe.SecretKey {
	return keygen.GenSecretKey()
}

func (keygen *KeyGenerator) GenPublicKey(sk *rlwe.SecretKey) *rlwe.PublicKey {
	return keygen.GenPublicKey(sk)
}

func (keygen *KeyGenerator) polyQPToPolyRs(polyQP rlwe.PolyQP, polyRs []*ring.Poly) {

	params := keygen.params
	beta := params.Beta()
	gamma := params.Gamma()

	ringR := params.RingR()

	// convert to ringR
	coeffsQ := polyQP.Q.GetCoefficients()
	coeffsP := polyQP.P.GetCoefficients()

	for i := 0; i < beta/gamma; i++ {

		//copy coeffcients
		for j := 0; j < gamma; j++ {
			copy(keygen.polyQPool.Coeffs[j], coeffsQ[i*gamma+j])
		}

		keygen.convQiR[i].ModUpQtoP(gamma-1, gamma, keygen.polyQPool, polyRs[i])

		ringR.NTT(polyRs[i], polyRs[i])
		ringR.MForm(polyRs[i], polyRs[i])
	}

	// special modulus part
	ringR.SetCoefficientsUint64(coeffsP[0], polyRs[beta/gamma])
	ringR.NTT(polyRs[beta/gamma], polyRs[beta/gamma])
	ringR.MForm(polyRs[beta/gamma], polyRs[beta/gamma])

}

func (keygen *KeyGenerator) GenRelinKey(sk *rlwe.SecretKey) (rlk *RelinKey) {

	params := keygen.params
	ringQP := params.RingQP()
	rlk = NewRelinKey(params)
	rlweRlk := keygen.GenRelinearizationKey(sk, 1).Keys[0]

	beta := params.Beta()
	alpha := params.Alpha()

	levelQ := beta - 1
	levelP := alpha - 1

	for i := 0; i < beta; i++ {
		ringQP.InvMFormLvl(levelQ, levelP, rlweRlk.Value[i][0], rlweRlk.Value[i][0])
		ringQP.InvNTTLvl(levelQ, levelP, rlweRlk.Value[i][0], rlweRlk.Value[i][0])
		keygen.polyQPToPolyRs(rlweRlk.Value[i][0], rlk.Value[0].Value[i])

		ringQP.InvMFormLvl(levelQ, levelP, rlweRlk.Value[i][1], rlweRlk.Value[i][1])
		ringQP.InvNTTLvl(levelQ, levelP, rlweRlk.Value[i][1], rlweRlk.Value[i][1])
		keygen.polyQPToPolyRs(rlweRlk.Value[i][1], rlk.Value[1].Value[i])
	}

	return
}
