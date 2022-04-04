package frlwe

import (
	"math"
	"math/big"
	"math/bits"
	"testing"

	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"github.com/tuneinsight/lattigo/v3/utils"

	"github.com/stretchr/testify/require"
)

var (
	PN15QP880 = ParametersLiteral{
		LogN: 15,
		Q: []uint64{ // 40 x 20
			0xffffe80001, 0xffffc40001,
			0xffffb20001, 0xffff940001,
			0xffff8a0001, 0xffff820001,
			0xffff780001, 0xffff750001,
			0xffff690001, 0xffff5b0001,
			0xffff580001, 0xffff550001,
			0xffff4b0001, 0xffff480001,
			0xffff420001, 0xffff340001,
			0xffff2d0001, 0xfffee90001,
			0xfffed10001, 0xfffeb60001,
		},
		P:     0x1fffffcf0001,                                 // 45
		R:     []uint64{0xffffffffffc0001, 0xfffffffff840001}, // 60 x 2 bit
		Sigma: rlwe.DefaultSigma,
	}
)

type testContext struct {
	params    Parameters
	ringQ     *ring.Ring
	prng      utils.PRNG
	uSamplerQ *ring.UniformSampler
	kgen      *KeyGenerator
	ksw       *KeySwitcher
	sk        *rlwe.SecretKey
	pk        *rlwe.PublicKey
	rlk       *RelinKey
	encryptor rlwe.Encryptor
	decryptor rlwe.Decryptor
}

func genTestParams(params Parameters) (testctx *testContext, err error) {

	testctx = new(testContext)
	testctx.params = params

	if testctx.prng, err = utils.NewPRNG(); err != nil {
		return nil, err
	}

	testctx.ringQ = params.RingQ()

	testctx.uSamplerQ = ring.NewUniformSampler(testctx.prng, testctx.ringQ)

	testctx.kgen = NewKeyGenerator(testctx.params)

	testctx.ksw = NewKeySwitcher(testctx.params)

	testctx.sk, testctx.pk = testctx.kgen.GenKeyPair()
	testctx.rlk = testctx.kgen.GenRelinKey(testctx.sk)

	testctx.encryptor = rlwe.NewEncryptor(testctx.params.Parameters, testctx.pk)
	testctx.decryptor = rlwe.NewDecryptor(testctx.params.Parameters, testctx.sk)

	return
}

// Returns the ceil(log2) of the sum of the absolute value of all the coefficients
func log2OfInnerSum(level int, ringQ *ring.Ring, poly *ring.Poly) (logSum int) {
	sumRNS := make([]uint64, level+1)
	var sum uint64
	for i := 0; i < level+1; i++ {

		qi := ringQ.Modulus[i]
		qiHalf := qi >> 1
		coeffs := poly.Coeffs[i]
		sum = 0

		for j := 0; j < ringQ.N; j++ {

			v := coeffs[j]

			if v >= qiHalf {
				sum = ring.CRed(sum+qi-v, qi)
			} else {
				sum = ring.CRed(sum+v, qi)
			}
		}

		sumRNS[i] = sum
	}

	var smallNorm = true
	for i := 1; i < level+1; i++ {
		smallNorm = smallNorm && (sumRNS[0] == sumRNS[i])
	}

	if !smallNorm {
		var qi uint64
		var crtReconstruction *big.Int

		sumBigInt := ring.NewUint(0)
		QiB := new(big.Int)
		tmp := new(big.Int)
		modulusBigint := ring.NewUint(1)

		for i := 0; i < level+1; i++ {

			qi = ringQ.Modulus[i]
			QiB.SetUint64(qi)

			modulusBigint.Mul(modulusBigint, QiB)

			crtReconstruction = new(big.Int)
			crtReconstruction.Quo(ringQ.ModulusBigint, QiB)
			tmp.ModInverse(crtReconstruction, QiB)
			tmp.Mod(tmp, QiB)
			crtReconstruction.Mul(crtReconstruction, tmp)

			sumBigInt.Add(sumBigInt, tmp.Mul(ring.NewUint(sumRNS[i]), crtReconstruction))
		}

		sumBigInt.Mod(sumBigInt, modulusBigint)

		logSum = sumBigInt.BitLen()
	} else {
		logSum = bits.Len64(sumRNS[0])
	}

	return
}

func TestFRLWE(t *testing.T) {
	params := NewParametersFromLiteral(PN15QP880)
	testctx, err := genTestParams(params)
	if err != nil {
		panic(err)
	}
	testInnerProduct(testctx, t)
}

func testInnerProduct(testctx *testContext, t *testing.T) {
	params := testctx.params
	ksw := testctx.ksw
	sk := testctx.sk
	ringQ := params.RingQ()

	t.Run("InnerProduct", func(t *testing.T) {
		a := ringQ.NewPoly()
		bg := testctx.kgen.GenSwitchingKey(sk)
		c := ringQ.NewPoly()

		testctx.uSamplerQ.Read(a)
		ksw.InternalProduct(params.MaxLevel(), a, bg, c)

		ringQ.NTT(c, c)
		ringQ.NTT(a, a)

		ringQ.MulCoeffsMontgomery(a, sk.Value.Q, a)
		ringQ.Sub(c, a, c)
		ringQ.InvNTT(c, c)

		log2Bound := bits.Len64(uint64(math.Floor(rlwe.DefaultSigma*6)) * uint64(params.N()))
		require.GreaterOrEqual(t, log2Bound, log2OfInnerSum(params.MaxLevel(), params.RingQ(), c))

	})

}
