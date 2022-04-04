package frlwe

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

type KeyGenerator struct {
	rlwe.KeyGenerator
	params Parameters
}

func NewKeyGenerator(params Parameters) (keygen *KeyGenerator) {
	keygen = new(KeyGenerator)
	keygen.KeyGenerator = rlwe.NewKeyGenerator(params.Parameters)
	keygen.params = params

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
	alpha := params.Alpha()
	beta := params.Beta()

	ringR := params.RingR()

	// convert to ringR
	coeffsQ := polyQP.Q.GetCoefficients()
	coeffsP := polyQP.P.GetCoefficients()

	for j := 0; j < beta; j++ {
		ringR.SetCoefficientsUint64(coeffsQ[j], polyRs[j])
		ringR.NTT(polyRs[j], polyRs[j])
		ringR.MForm(polyRs[j], polyRs[j])
	}

	for j := beta; j < alpha+beta; j++ {
		ringR.SetCoefficientsUint64(coeffsP[j-beta], polyRs[j])
		ringR.NTT(polyRs[j], polyRs[j])
		ringR.MForm(polyRs[j], polyRs[j])
	}
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
