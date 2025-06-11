// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file is a modified version of code originally from the Lattigo project:
// https://github.com/ldsec/lattigo
// Licensed under the Apache License, Version 2.0.

package rlwe

import (
	"math"
	"math/big"

	"fast-ksw/ring"
	"fast-ksw/utils"
)

// KeyGenerator is an interface implementing the methods of the KeyGenerator.
type KeyGenerator interface {
	GenSecretKey() (sk *SecretKey)
	GenSecretKeyGaussian() (sk *SecretKey)
	GenSecretKeyWithDistrib(p float64) (sk *SecretKey)
	GenSecretKeyWithHammingWeight(hw int) (sk *SecretKey)
	GenPublicKey(sk *SecretKey) (pk *PublicKey)
	GenKeyPair() (sk *SecretKey, pk *PublicKey)
	GenRelinearizationKey(sk *SecretKey, maxDegree int) (evk *RelinearizationKey)
	GenSwitchingKey(skInput, skOutput *SecretKey) (newevakey *SwitchingKey)
	GenSwitchingKeyForGalois(galEl uint64, sk *SecretKey) (swk *SwitchingKey)
	GenRotationKeys(galEls []uint64, sk *SecretKey) (rks *RotationKeySet)
	GenSwitchingKeyForRotationBy(k int, sk *SecretKey) (swk *SwitchingKey)
	GenRotationKeysForRotations(ks []int, inclueSwapRows bool, sk *SecretKey) (rks *RotationKeySet)
	GenSwitchingKeyForRowRotation(sk *SecretKey) (swk *SwitchingKey)
	GenRotationKeysForInnerSum(sk *SecretKey) (rks *RotationKeySet)
	GenSwitchingKeysForRingSwap(skCKKS, skCI *SecretKey) (swkStdToConjugateInvariant, swkConjugateInvariantToStd *SwitchingKey)
}

// KeyGenerator is a structure that stores the elements required to create new keys,
// as well as a small memory pool for intermediate values.
type keyGenerator struct {
	params           Parameters
	poolQ            *ring.Poly
	poolQP           PolyQP
	ternarySampler   *ring.TernarySampler
	gaussianSamplerQ *ring.GaussianSampler
	uniformSamplerQ  *ring.UniformSampler
	uniformSamplerP  *ring.UniformSampler
}

// NewKeyGenerator creates a new KeyGenerator, from which the secret and public keys, as well as the evaluation,
// rotation and switching keys can be generated.
func NewKeyGenerator(params Parameters) KeyGenerator {

	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}

	var poolQP PolyQP
	var uniformSamplerP *ring.UniformSampler
	if params.PCount() > 0 {
		poolQP = params.RingQP().NewPoly()
		uniformSamplerP = ring.NewUniformSampler(prng, params.RingP())
	}

	return &keyGenerator{
		params:           params,
		poolQ:            params.RingQ().NewPoly(),
		poolQP:           poolQP,
		ternarySampler:   ring.NewTernarySamplerWithHammingWeight(prng, params.ringQ, params.h, false),
		gaussianSamplerQ: ring.NewGaussianSampler(prng, params.RingQ(), params.Sigma(), int(6*params.Sigma())),
		uniformSamplerQ:  ring.NewUniformSampler(prng, params.RingQ()),
		uniformSamplerP:  uniformSamplerP,
	}
}

// GenSecretKey generates a new SecretKey with the distribution [1/3, 1/3, 1/3].
func (keygen *keyGenerator) GenSecretKey() (sk *SecretKey) {
	return keygen.genSecretKeyFromSampler(keygen.ternarySampler)
}

// GenSecretKey generates a new SecretKey with the error distribution.
func (keygen *keyGenerator) GenSecretKeyGaussian() (sk *SecretKey) {
	return keygen.genSecretKeyFromSampler(keygen.gaussianSamplerQ)
}

// GenSecretKeyWithDistrib generates a new SecretKey with the distribution [(p-1)/2, p, (p-1)/2].
func (keygen *keyGenerator) GenSecretKeyWithDistrib(p float64) (sk *SecretKey) {
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}
	ternarySamplerMontgomery := ring.NewTernarySampler(prng, keygen.params.RingQ(), p, false)
	return keygen.genSecretKeyFromSampler(ternarySamplerMontgomery)
}

// GenSecretKeyWithHammingWeight generates a new SecretKey with exactly hw non-zero coefficients.
func (keygen *keyGenerator) GenSecretKeyWithHammingWeight(hw int) (sk *SecretKey) {
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}
	ternarySamplerMontgomery := ring.NewTernarySamplerWithHammingWeight(prng, keygen.params.RingQ(), hw, false)
	return keygen.genSecretKeyFromSampler(ternarySamplerMontgomery)
}

// genSecretKeyFromSampler generates a new SecretKey sampled from the provided Sampler.
func (keygen *keyGenerator) genSecretKeyFromSampler(sampler ring.Sampler) (sk *SecretKey) {
	sk = new(SecretKey)
	if keygen.params.PCount() > 0 {
		ringQP := keygen.params.RingQP()
		sk.Value = ringQP.NewPoly()
		levelQ, levelP := keygen.params.QCount()-1, keygen.params.PCount()-1
		sampler.Read(sk.Value.Q)
		ringQP.ExtendBasisSmallNormAndCenter(sk.Value.Q, levelP, nil, sk.Value.P)
		ringQP.NTTLvl(levelQ, levelP, sk.Value, sk.Value)
		ringQP.MFormLvl(levelQ, levelP, sk.Value, sk.Value)
	} else {
		ringQ := keygen.params.RingQ()
		sk = new(SecretKey)
		sk.Value.Q = ringQ.NewPoly()
		sampler.Read(sk.Value.Q)
		ringQ.NTT(sk.Value.Q, sk.Value.Q)
		ringQ.MForm(sk.Value.Q, sk.Value.Q)
	}

	return
}

// GenPublicKey generates a new public key from the provided SecretKey.
func (keygen *keyGenerator) GenPublicKey(sk *SecretKey) (pk *PublicKey) {

	pk = new(PublicKey)

	if keygen.params.PCount() > 0 {

		ringQP := keygen.params.RingQP()
		levelQ, levelP := keygen.params.QCount()-1, keygen.params.PCount()-1

		//pk[0] = [-as + e]
		//pk[1] = [a]
		pk = NewPublicKey(keygen.params)
		keygen.gaussianSamplerQ.Read(pk.Value[0].Q)
		ringQP.ExtendBasisSmallNormAndCenter(pk.Value[0].Q, levelP, nil, pk.Value[0].P)
		ringQP.NTTLvl(levelQ, levelP, pk.Value[0], pk.Value[0])

		keygen.uniformSamplerQ.Read(pk.Value[1].Q)
		keygen.uniformSamplerP.Read(pk.Value[1].P)

		ringQP.MulCoeffsMontgomeryAndSubLvl(levelQ, levelP, sk.Value, pk.Value[1], pk.Value[0])
	} else {
		ringQ := keygen.params.RingQ()

		//pk[0] = [-as + e]
		//pk[1] = [a]
		pk = NewPublicKey(keygen.params)
		keygen.gaussianSamplerQ.Read(pk.Value[0].Q)

		ringQ.NTT(pk.Value[0].Q, pk.Value[0].Q)

		keygen.uniformSamplerQ.Read(pk.Value[1].Q)

		ringQ.MulCoeffsMontgomeryAndSub(sk.Value.Q, pk.Value[1].Q, pk.Value[0].Q)
	}
	return pk
}

// GenKeyPair generates a new SecretKey with distribution [1/3, 1/3, 1/3] and a corresponding public key.
func (keygen *keyGenerator) GenKeyPair() (sk *SecretKey, pk *PublicKey) {
	sk = keygen.GenSecretKey()
	return sk, keygen.GenPublicKey(sk)
}

// GenRelinKey generates a new EvaluationKey that will be used to relinearize Ciphertexts during multiplication.
func (keygen *keyGenerator) GenRelinearizationKey(sk *SecretKey, maxDegree int) (evk *RelinearizationKey) {

	if keygen.params.PCount() == 0 {
		panic("modulus P is empty")
	}

	levelQ := keygen.params.QCount() - 1
	levelP := keygen.params.PCount() - 1

	evk = new(RelinearizationKey)
	evk.Keys = make([]*SwitchingKey, maxDegree)
	for i := range evk.Keys {
		evk.Keys[i] = NewSwitchingKey(keygen.params, levelQ, levelP)
	}

	keygen.poolQP.Q.CopyValues(sk.Value.Q)
	ringQ := keygen.params.RingQ()
	for i := 0; i < maxDegree; i++ {
		ringQ.MulCoeffsMontgomery(keygen.poolQP.Q, sk.Value.Q, keygen.poolQP.Q)
		keygen.genSwitchingKey(keygen.poolQP.Q, sk.Value, evk.Keys[i])
	}

	return
}

// GenRotationKeys generates a RotationKeySet from a list of galois element corresponding to the desired rotations
// See also GenRotationKeysForRotations.
func (keygen *keyGenerator) GenRotationKeys(galEls []uint64, sk *SecretKey) (rks *RotationKeySet) {
	rks = NewRotationKeySet(keygen.params, galEls)
	for _, galEl := range galEls {
		keygen.genrotKey(sk.Value, keygen.params.InverseGaloisElement(galEl), rks.Keys[galEl])
	}
	return rks
}

func (keygen *keyGenerator) GenSwitchingKeyForRotationBy(k int, sk *SecretKey) (swk *SwitchingKey) {
	swk = NewSwitchingKey(keygen.params, keygen.params.QCount()-1, keygen.params.PCount()-1)
	galElInv := keygen.params.GaloisElementForColumnRotationBy(-int(k))
	keygen.genrotKey(sk.Value, galElInv, swk)
	return
}

// GenRotationKeysForRotations generates a RotationKeySet supporting left rotations by k positions for all k in ks.
// Negative k is equivalent to a right rotation by k positions
// If includeConjugate is true, the resulting set contains the conjugation key.
func (keygen *keyGenerator) GenRotationKeysForRotations(ks []int, includeConjugate bool, sk *SecretKey) (rks *RotationKeySet) {
	galEls := make([]uint64, len(ks), len(ks)+1)
	for i, k := range ks {
		galEls[i] = keygen.params.GaloisElementForColumnRotationBy(k)
	}
	if includeConjugate {
		galEls = append(galEls, keygen.params.GaloisElementForRowRotation())
	}
	return keygen.GenRotationKeys(galEls, sk)
}

func (keygen *keyGenerator) GenSwitchingKeyForRowRotation(sk *SecretKey) (swk *SwitchingKey) {
	swk = NewSwitchingKey(keygen.params, keygen.params.QCount()-1, keygen.params.PCount()-1)
	keygen.genrotKey(sk.Value, keygen.params.GaloisElementForRowRotation(), swk)
	return
}

func (keygen *keyGenerator) GenSwitchingKeyForGalois(galoisEl uint64, sk *SecretKey) (swk *SwitchingKey) {
	swk = NewSwitchingKey(keygen.params, keygen.params.QCount()-1, keygen.params.PCount()-1)
	keygen.genrotKey(sk.Value, keygen.params.InverseGaloisElement(galoisEl), swk)
	return
}

// GenRotationKeysForInnerSum generates a RotationKeySet supporting the InnerSum operation of the Evaluator
func (keygen *keyGenerator) GenRotationKeysForInnerSum(sk *SecretKey) (rks *RotationKeySet) {
	return keygen.GenRotationKeys(keygen.params.GaloisElementsForRowInnerSum(), sk)
}

func (keygen *keyGenerator) genrotKey(sk PolyQP, galEl uint64, swk *SwitchingKey) {

	skIn := sk
	skOut := keygen.poolQP
	ringQ := keygen.params.RingQ()

	index := ringQ.PermuteNTTIndex(galEl)
	ringQ.PermuteNTTWithIndexLvl(keygen.params.QCount()-1, skIn.Q, index, skOut.Q)
	ringQ.PermuteNTTWithIndexLvl(keygen.params.PCount()-1, skIn.P, index, skOut.P)

	keygen.genSwitchingKey(skIn.Q, skOut, swk)
}

// GenSwitchingKeysForRingSwap generates the necessary switching keys to switch from a standard ring to to a conjugate invariant ring and vice-versa.
func (keygen *keyGenerator) GenSwitchingKeysForRingSwap(skStd, skConjugateInvariant *SecretKey) (swkStdToConjugateInvariant, swkConjugateInvariantToStd *SwitchingKey) {

	skCIMappedToStandard := &SecretKey{Value: keygen.poolQP}
	keygen.params.RingQ().UnfoldConjugateInvariantToStandard(skConjugateInvariant.Value.Q.Level(), skConjugateInvariant.Value.Q, skCIMappedToStandard.Value.Q)
	keygen.params.RingQ().UnfoldConjugateInvariantToStandard(skConjugateInvariant.Value.P.Level(), skConjugateInvariant.Value.P, skCIMappedToStandard.Value.P)

	swkConjugateInvariantToStd = keygen.GenSwitchingKey(skCIMappedToStandard, skStd)
	swkStdToConjugateInvariant = keygen.GenSwitchingKey(skStd, skCIMappedToStandard)
	return
}

// GenSwitchingKey generates a new key-switching key, that will re-encrypt a Ciphertext encrypted under the input key into the output key.
// If the ringDegree(skOutput) > ringDegree(skInput),  generates [-a*SkOut + w*P*skIn_{Y^{N/n}} + e, a] in X^{N}.
// If the ringDegree(skOutput) < ringDegree(skInput),  generates [-a*skOut_{Y^{N/n}} + w*P*skIn + e_{N}, a_{N}] in X^{N}.
// Else generates [-a*skOut + w*P*skIn + e, a] in X^{N}.
// The output switching key is always given in max(N, n) and in the moduli of the output switching key.
// When key-switching a ciphertext from Y^{N/n} to X^{N}, the ciphertext must first be mapped to X^{N}
// using SwitchCiphertextRingDegreeNTT(ctSmallDim, nil, ctLargeDim).
// When key-switching a ciphertext from X^{N} to Y^{N/n}, the output of the key-switch is in still X^{N} and
// must be mapped Y^{N/n} using SwitchCiphertextRingDegreeNTT(ctLargeDim, ringQLargeDim, ctSmallDim).
func (keygen *keyGenerator) GenSwitchingKey(skInput, skOutput *SecretKey) (swk *SwitchingKey) {

	if keygen.params.PCount() == 0 {
		panic("Cannot GenSwitchingKey: modulus P is empty")
	}

	swk = NewSwitchingKey(keygen.params, skOutput.Value.Q.Level(), skOutput.Value.P.Level())

	if len(skInput.Value.Q.Coeffs[0]) > len(skOutput.Value.Q.Coeffs[0]) { // N -> n
		ring.MapSmallDimensionToLargerDimensionNTT(skOutput.Value.Q, keygen.poolQP.Q)
		ring.MapSmallDimensionToLargerDimensionNTT(skOutput.Value.P, keygen.poolQP.P)
		keygen.genSwitchingKey(skInput.Value.Q, keygen.poolQP, swk)
	} else { // N -> N or n -> N
		ring.MapSmallDimensionToLargerDimensionNTT(skInput.Value.Q, keygen.poolQ)

		if skInput.Value.Q.Level() < skOutput.Value.Q.Level() {

			ringQ := keygen.params.RingQ()

			ringQ.InvNTTLvl(0, keygen.poolQ, keygen.poolQP.Q)
			ringQ.InvMFormLvl(0, keygen.poolQP.Q, keygen.poolQP.Q)

			Q := ringQ.Modulus[0]
			QHalf := Q >> 1

			polQ := keygen.poolQP.Q
			polP := keygen.poolQ
			var sign uint64
			for j := 0; j < ringQ.N; j++ {

				coeff := polQ.Coeffs[0][j]

				sign = 1
				if coeff > QHalf {
					coeff = Q - coeff
					sign = 0
				}

				for i := skInput.Value.Q.Level() + 1; i < skOutput.Value.Q.Level()+1; i++ {
					polP.Coeffs[i][j] = (coeff * sign) | (ringQ.Modulus[i]-coeff)*(sign^1)
				}
			}

			for i := skInput.Value.Q.Level() + 1; i < skOutput.Value.Q.Level()+1; i++ {
				ringQ.NTTSingle(i, polP.Coeffs[i], polP.Coeffs[i])
				ring.MFormVec(polP.Coeffs[i], polP.Coeffs[i], ringQ.Modulus[i], ringQ.BredParams[i])
			}
		}

		keygen.genSwitchingKey(keygen.poolQ, skOutput.Value, swk)
	}

	return
}

func (keygen *keyGenerator) genSwitchingKey(skIn *ring.Poly, skOut PolyQP, swk *SwitchingKey) {

	ringQ := keygen.params.RingQ()
	ringQP := keygen.params.RingQP()

	levelQ := len(swk.Value[0][0].Q.Coeffs) - 1
	levelP := len(swk.Value[0][0].P.Coeffs) - 1

	var pBigInt *big.Int
	if levelP == keygen.params.PCount()-1 {
		pBigInt = keygen.params.RingP().ModulusBigint
	} else {
		P := keygen.params.RingP().Modulus
		pBigInt = new(big.Int).SetUint64(P[0])
		for i := 1; i < levelP+1; i++ {
			pBigInt.Mul(pBigInt, ring.NewUint(P[i]))
		}
	}

	// Computes P * skIn
	ringQ.MulScalarBigintLvl(levelQ, skIn, pBigInt, keygen.poolQ)

	alpha := levelP + 1
	beta := int(math.Ceil(float64(levelQ+1) / float64(levelP+1)))

	var index int
	for i := 0; i < beta; i++ {

		// e
		keygen.gaussianSamplerQ.ReadLvl(levelQ, swk.Value[i][0].Q)
		ringQP.ExtendBasisSmallNormAndCenter(swk.Value[i][0].Q, levelP, nil, swk.Value[i][0].P)
		ringQP.NTTLazyLvl(levelQ, levelP, swk.Value[i][0], swk.Value[i][0])
		ringQP.MFormLvl(levelQ, levelP, swk.Value[i][0], swk.Value[i][0])

		// a (since a is uniform, we consider we already sample it in the NTT and Montgomery domain)
		keygen.uniformSamplerQ.ReadLvl(levelQ, swk.Value[i][1].Q)
		keygen.uniformSamplerP.ReadLvl(levelP, swk.Value[i][1].P)

		// e + (skIn * P) * (q_star * q_tild) mod QP
		//
		// q_prod = prod(q[i*alpha+j])
		// q_star = Q/qprod
		// q_tild = q_star^-1 mod q_prod
		//
		// Therefore : (skIn * P) * (q_star * q_tild) = sk*P mod q[i*alpha+j], else 0
		for j := 0; j < alpha; j++ {

			index = i*alpha + j

			// It handles the case where nb pj does not divide nb qi
			if index >= levelQ+1 {
				break
			}

			qi := ringQ.Modulus[index]
			p0tmp := keygen.poolQ.Coeffs[index]
			p1tmp := swk.Value[i][0].Q.Coeffs[index]

			for w := 0; w < ringQ.N; w++ {
				p1tmp[w] = ring.CRed(p1tmp[w]+p0tmp[w], qi)
			}
		}

		// (skIn * P) * (q_star * q_tild) - a * skOut + e mod QP
		ringQP.MulCoeffsMontgomeryAndSubLvl(levelQ, levelP, swk.Value[i][1], skOut, swk.Value[i][0])
	}
}
