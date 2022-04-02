package frlwe

import (
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

type KeyGenerator struct {
	keygen rlwe.KeyGenerator
	params Parameters
}

func NewKeyGenerator(params Parameters) (keygen *KeyGenerator) {
	keygen = new(KeyGenerator)
	keygen.keygen = rlwe.NewKeyGenerator(params.Parameters)
	keygen.params = params

	return
}

func (keygen *KeyGenerator) GenSecretKey() *rlwe.SecretKey {
	return keygen.keygen.GenSecretKey()
}

func (keygen *KeyGenerator) GenPublicKey(sk *rlwe.SecretKey) *rlwe.PublicKey {
	return keygen.keygen.GenPublicKey(sk)
}

func (keygen *KeyGenerator) GenRelinKey(sk *rlwe.SecretKey) (rlk *RelinKey) {

	params := keygen.params
	ringR := params.RingR()
	rlk = NewRelinKey(params)
	rlweRlk := keygen.keygen.GenRelinearizationKey(sk, 1)

	gadgetDim := params.Beta()

	for idx := 0; idx < 2; idx++ {
		for i := 0; i < gadgetDim; i++ {
			rlkPolyQP := rlweRlk.Keys[0].Value[i][idx]

			params.RingQ().InvMForm(rlkPolyQP.Q, rlkPolyQP.Q)
			params.RingQ().InvNTT(rlkPolyQP.Q, rlkPolyQP.Q)

			params.RingP().InvMForm(rlkPolyQP.P, rlkPolyQP.P)
			params.RingP().InvNTT(rlkPolyQP.P, rlkPolyQP.P)

			coeffsQ := rlkPolyQP.Q.GetCoefficients()
			coeffsP := rlkPolyQP.P.GetCoefficients()

			for j := 0; j < params.Beta(); j++ {
				rlkPolyR := rlk.Value[idx].Value[i][j]
				ringR.SetCoefficientsUint64(coeffsQ[j], rlkPolyR)
				ringR.NTT(rlkPolyR, rlkPolyR)
				ringR.MForm(rlkPolyR, rlkPolyR)
			}

			for j := 0; j < params.Alpha(); j++ {
				rlkPolyR := rlk.Value[idx].Value[i][j+params.Beta()]
				ringR.SetCoefficientsUint64(coeffsP[j], rlkPolyR)
				ringR.NTT(rlkPolyR, rlkPolyR)
				ringR.MForm(rlkPolyR, rlkPolyR)
			}
		}
	}

	return
}
