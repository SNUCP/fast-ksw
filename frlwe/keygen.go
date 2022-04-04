package frlwe

import (
	"github.com/tuneinsight/lattigo/v3/rlwe"

	"math/big"
)

type KeyGenerator struct {
	rlwe.KeyGenerator
	params     Parameters
	polyQPPool rlwe.PolyQP
}

func NewKeyGenerator(params Parameters) (keygen *KeyGenerator) {
	keygen = new(KeyGenerator)
	keygen.KeyGenerator = rlwe.NewKeyGenerator(params.Parameters)
	keygen.params = params
	keygen.polyQPPool = params.RingQP().NewPoly()

	return
}

func (keygen *KeyGenerator) GenSecretKey() *rlwe.SecretKey {
	return keygen.GenSecretKey()
}

func (keygen *KeyGenerator) GenPublicKey(sk *rlwe.SecretKey) *rlwe.PublicKey {
	return keygen.GenPublicKey(sk)
}

func (keygen *KeyGenerator) GenSwitchingKey(sk *rlwe.SecretKey) (swk *SwitchingKey) {
	params := keygen.params
	swk = NewSwitchingKey(params)

	ringQ := params.RingQ()
	ringP := params.RingP()
	ringR := params.RingR()

	alpha := params.Alpha()
	beta := params.Beta()

	for i := 0; i < beta; i++ {
		gi := big.NewInt(1)
		qi := big.NewInt(int64(ringQ.Modulus[i]))
		gi.Div(ringQ.ModulusBigint, qi)
		qiHat := big.NewInt(1).ModInverse(gi, qi)
		gi.Mul(qiHat, gi)
		gi.Mul(gi, ringP.ModulusBigint)

		ringQ.InvMForm(sk.Value.Q, keygen.polyQPPool.Q)
		ringQ.InvNTT(keygen.polyQPPool.Q, keygen.polyQPPool.Q)
		ringQ.MulScalarBigint(keygen.polyQPPool.Q, gi, keygen.polyQPPool.Q)

		ringP.InvMForm(sk.Value.P, keygen.polyQPPool.P)
		ringP.InvNTT(keygen.polyQPPool.P, keygen.polyQPPool.P)
		ringP.MulScalarBigint(keygen.polyQPPool.P, gi, keygen.polyQPPool.P)

		coeffsQ := keygen.polyQPPool.Q.GetCoefficients()
		coeffsP := keygen.polyQPPool.P.GetCoefficients()

		for j := 0; j < beta; j++ {
			ringR.SetCoefficientsUint64(coeffsQ[j], swk.Value[i][j])
			ringR.NTT(swk.Value[i][j], swk.Value[i][j])
			ringR.MForm(swk.Value[i][j], swk.Value[i][j])
		}

		for j := beta; j < alpha+beta; j++ {
			ringR.SetCoefficientsUint64(coeffsP[j-beta], swk.Value[i][j])
			ringR.NTT(swk.Value[i][j], swk.Value[i][j])
			ringR.MForm(swk.Value[i][j], swk.Value[i][j])
		}
	}

	return
}

func (keygen *KeyGenerator) GenRelinKey(sk *rlwe.SecretKey) (rlk *RelinKey) {

	params := keygen.params
	ringR := params.RingR()
	rlk = NewRelinKey(params)
	rlweRlk := keygen.GenRelinearizationKey(sk, 1)

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
