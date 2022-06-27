package frlwe

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"

	"math"
)

type KeyGenerator struct {
	rlwe.KeyGenerator
	params Parameters

	ringQi     []*ring.Ring
	convQiR    []*ring.BasisExtender
	polyQiPool *ring.Poly

	ringPi     []*ring.Ring
	convPiR    []*ring.BasisExtender
	polyPiPool *ring.Poly
}

func NewKeyGenerator(params Parameters) (keygen *KeyGenerator) {
	keygen = new(KeyGenerator)
	keygen.KeyGenerator = rlwe.NewKeyGenerator(params.Parameters)
	keygen.params = params

	level := params.MaxLevel()
	alpha := params.Alpha()
	gamma := params.Gamma()

	blockLenQi := int(math.Ceil(float64(level+1) / float64(gamma)))
	blockLenPi := int(math.Ceil(float64(alpha) / float64(gamma)))

	keygen.ringQi = make([]*ring.Ring, blockLenQi)
	keygen.convQiR = make([]*ring.BasisExtender, blockLenQi)

	keygen.ringPi = make([]*ring.Ring, blockLenPi)
	keygen.convPiR = make([]*ring.BasisExtender, blockLenPi)

	ringQ := params.RingQ()
	ringP := params.RingP()

	for i := 0; i < blockLenQi; i++ {
		modulusQi := make([]uint64, 0)
		for j := 0; j < gamma; j++ {
			if i*gamma+j < level+1 {
				modulusQi = append(modulusQi, ringQ.Modulus[i*gamma+j])
			}
		}

		keygen.ringQi[i], _ = ring.NewRing(params.N(), modulusQi)
		keygen.convQiR[i] = ring.NewBasisExtender(keygen.ringQi[i], params.RingR())
	}
	keygen.polyQiPool = params.RingQ().NewPolyLvl(gamma - 1)

	for i := 0; i < blockLenPi; i++ {
		modulusPi := make([]uint64, 0)
		for j := 0; j < gamma; j++ {
			if i*gamma+j < alpha {
				modulusPi = append(modulusPi, ringP.Modulus[i*gamma+j])
			}
		}

		keygen.ringPi[i], _ = ring.NewRing(params.N(), modulusPi)
		keygen.convPiR[i] = ring.NewBasisExtender(keygen.ringPi[i], params.RingR())
	}
	keygen.polyPiPool = params.RingQ().NewPolyLvl(gamma - 1)

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

	level := params.MaxLevel()
	alpha := params.Alpha()
	gamma := params.Gamma()

	ringR := params.RingR()

	coeffsQ := polyQP.Q.GetCoefficients()
	coeffsP := polyQP.P.GetCoefficients()

	blockLenQi := int(math.Ceil(float64(level+1) / float64(gamma)))
	blockLenPi := int(math.Ceil(float64(alpha) / float64(gamma)))

	// embedd ringQi into ringR
	for i := 0; i < blockLenQi; i++ {

		levelQi := 0
		for j := 0; j < gamma; j++ {
			if i*gamma+j < level+1 {
				levelQi++
				copy(keygen.polyQiPool.Coeffs[j], coeffsQ[i*gamma+j])
			}
		}

		keygen.convQiR[i].ModUpQtoP(levelQi, gamma+alpha-1, keygen.polyQiPool, polyRs[i])

		ringR.NTT(polyRs[i], polyRs[i])
		ringR.MForm(polyRs[i], polyRs[i])
	}

	// embedd ringP into ringR
	for i := 0; i < blockLenPi; i++ {

		levelPi := 0
		for j := 0; j < gamma; j++ {
			if i*gamma+j < alpha {
				levelPi++
				copy(keygen.polyPiPool.Coeffs[j], coeffsP[i*gamma+j])
			}
		}

		keygen.convPiR[i].ModUpQtoP(levelPi, gamma+alpha-1, keygen.polyPiPool, polyRs[i+blockLenQi])

		ringR.NTT(polyRs[i+blockLenQi], polyRs[i+blockLenQi])
		ringR.MForm(polyRs[i+blockLenQi], polyRs[i+blockLenQi])
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
		keygen.polyQPToPolyRs(rlweRlk.Value[i][0], rlk.Value[0].Value[i])

		ringQP.InvMFormLvl(levelQ, levelP, rlweRlk.Value[i][1], rlweRlk.Value[i][1])
		ringQP.InvNTTLvl(levelQ, levelP, rlweRlk.Value[i][1], rlweRlk.Value[i][1])
		keygen.polyQPToPolyRs(rlweRlk.Value[i][1], rlk.Value[1].Value[i])
	}

	return
}
