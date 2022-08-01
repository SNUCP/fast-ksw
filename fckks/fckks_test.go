package fckks

import (
	"math"
	"testing"

	"fast-ksw/frlwe"

	"fast-ksw/ckks"
	"fast-ksw/ring"
	"fast-ksw/rlwe"
	"fast-ksw/utils"

	"github.com/stretchr/testify/require"
)

var (
	PN15QP870 = ParametersLiteral{
		LogN: 15,
		Q: []uint64{ // 45 x 18
			0x1fffffcf0001, 0x1fffffc20001,
			0x1fffffbf0001, 0x1fffffb10001,
			0x1fffff980001, 0x1fffff950001,
			0x1fffff7e0001, 0x1fffff750001,
			0x1fffff690001, 0x1fffff630001,
			0x1fffff360001, 0x1fffff1b0001,
			0x1fffff060001, 0x1ffffefd0001,
			0x1ffffef30001, 0x1ffffede0001,
			//0x1ffffeca0001, 0x1ffffec30001,
		},

		P: []uint64{ // 50 x 4
			0x3ffffffd20001, 0x3ffffffb80001,
			0x3fffffed60001, 0x3fffffec80001,
		},

		T: []uint64{ // 55 x 8 bit
			0x7fffffffba0001, 0x7fffffffaa0001,
			0x7fffffff7e0001, 0x7fffffff380001,
			0x7ffffffef00001, 0x7ffffffeba0001,
			0x7ffffffeac0001, 0x7ffffffe700001,
		},

		Sigma:        rlwe.DefaultSigma,
		DefaultScale: 1 << 45,
		LogSlots:     14,
	}

	PN16QP1760 = ParametersLiteral{
		LogN: 16,
		Q: []uint64{ // 59 + 43 x 33
			0x7ffffffffcc0001,

			0x7ffffd20001, 0x7ffffaa0001,
			0x7ffffa80001, 0x7ffff8c0001,
			0x7ffff620001, 0x7ffff380001,
			0x7ffff360001, 0x7ffff260001,
			0x7fffe7c0001, 0x7fffe660001,
			0x7fffe600001, 0x7fffe460001,
			0x7fffe1e0001, 0x7fffde60001,
			0x7fffdd00001, 0x7fffd740001,
			0x7fffd6e0001, 0x7fffd5c0001,
			0x7fffd520001, 0x7fffd2e0001,
			0x7fffd200001, 0x7fffd140001,
			0x7fffcc20001, 0x7fffca40001,
			0x7fffc980001, 0x7fffc680001,
			0x7fffc620001, 0x7fffc600001,
			0x7fffc480001, 0x7fffc380001,
			0x7fffc300001, 0x7fffc1a0001,
			0x7fffc180001, 0x7fffbf40001,
			0x7fffbd00001,
		},
		P: []uint64{ // 45 x 6
			0x1fffffc20001, 0x1fffff980001,
			0x1fffff7e0001, 0x1fffff360001,
			//0x1fffff060001, 0x1ffffede0001,
		},

		T: []uint64{ // 50 x 12
			0x3ffffffd20001, 0x3ffffffb80001,
			0x3fffffed60001, 0x3fffffec80001,
			0x3fffffebe0001, 0x3fffffea60001,
			0x3fffffea40001, 0x3fffffe9e0001,
			0x3fffffe9a0001, 0x3fffffe940001,
			//0x3fffffe620001, 0x3fffffe460001,
			//0x3fffffdd40001, 0x3fffffdce0001,
			//0x3fffffd900001, 0x3fffffd7a0001,
			//0x3fffffd540001, 0x3fffffd500001,
			//0x3fffffd2a0001, 0x3fffffcc40001,
		},

		Sigma:        rlwe.DefaultSigma,
		DefaultScale: 1 << 43,
		LogSlots:     15,
	}
)

type testContext struct {
	params  Parameters
	ringQ   *ring.Ring
	kgen    *frlwe.KeyGenerator
	sk      *rlwe.SecretKey
	pk      *rlwe.PublicKey
	rlk     *frlwe.RelinKey
	enc     *Encryptor
	dec     *Decryptor
	eval    *Evaluator
	evalOld ckks.Evaluator
}

func genTestParams(params Parameters) (testctx *testContext, err error) {

	testctx = new(testContext)
	testctx.params = params

	testctx.ringQ = params.RingQ()

	testctx.kgen = frlwe.NewKeyGenerator(testctx.params.frlweParams)

	testctx.sk, testctx.pk = testctx.kgen.GenKeyPair()
	testctx.rlk = testctx.kgen.GenRelinKey(testctx.sk)

	testctx.enc = NewEncryptor(testctx.params, testctx.pk)
	testctx.dec = NewDecryptor(testctx.params, testctx.sk)
	testctx.eval = NewEvaluator(testctx.params)

	rlkOld := testctx.kgen.KeyGenerator.GenRelinearizationKey(testctx.sk, 1)
	testctx.evalOld = ckks.NewEvaluator(testctx.params.Parameters, rlwe.EvaluationKey{Rlk: rlkOld})

	return
}

func newTestVectors(testctx *testContext, a, b complex128) (msg *Message, ciphertext *ckks.Ciphertext) {

	params := testctx.params
	logSlots := params.LogSlots()

	msg = NewMessage(params)

	for i := 0; i < 1<<logSlots; i++ {
		msg.Value[i] = complex(utils.RandFloat64(real(a), real(b)), utils.RandFloat64(imag(a), imag(b)))
	}

	ciphertext = testctx.enc.EncryptMsgNew(msg)

	return msg, ciphertext
}

func TestFCKKS(t *testing.T) {
	params := NewParametersFromLiteral(PN16QP1760)
	testctx, err := genTestParams(params)
	if err != nil {
		panic(err)
	}

	testEncrypt(testctx, t)
	testEval(testctx, t)
}

func testEncrypt(testctx *testContext, t *testing.T) {

	params := testctx.params
	slots := params.Slots()
	dec := testctx.dec

	t.Run("Encrypt & Decrypt", func(t *testing.T) {
		msg, ctxt := newTestVectors(testctx, complex(-1, -1), complex(1, 1))
		msgOut := dec.DecryptToMsgNew(ctxt)
		for i := 0; i < slots; i++ {
			delta := msg.Value[i] - msgOut.Value[i]
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+8, math.Log2(math.Abs(real(delta))))
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+8, math.Log2(math.Abs(imag(delta))))
		}
	})
}

func testEval(testctx *testContext, t *testing.T) {

	params := testctx.params
	slots := params.Slots()
	dec := testctx.dec
	eval := testctx.eval
	evalOld := testctx.evalOld

	t.Run("Add", func(t *testing.T) {
		msg1, ct0 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))
		msg2, ct1 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))

		ctOut := eval.AddNew(ct0, ct1)

		msgOut := dec.DecryptToMsgNew(ctOut)

		for i := 0; i < slots; i++ {
			delta := msg1.Value[i] + msg2.Value[i] - msgOut.Value[i]
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+9, math.Log2(math.Abs(real(delta))))
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+9, math.Log2(math.Abs(imag(delta))))

		}
	})

	t.Run("MulAndRelin", func(t *testing.T) {
		msg1, ct0 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))
		msg2, ct1 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))

		ctOut := eval.MulRelinNew(ct0, ct1, testctx.rlk)

		require.Equal(t, ctOut.Degree(), 1)

		msgOut := dec.DecryptToMsgNew(ctOut)

		for i := 0; i < slots; i++ {
			delta := msg1.Value[i]*msg2.Value[i] - msgOut.Value[i]
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+12, math.Log2(math.Abs(real(delta))))
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+12, math.Log2(math.Abs(imag(delta))))
		}
	})

	t.Run("MulAndRelinOld", func(t *testing.T) {
		msg1, ct0 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))
		msg2, ct1 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))

		ctOut := evalOld.MulRelinNew(ct0, ct1)

		require.Equal(t, ctOut.Degree(), 1)

		msgOut := dec.DecryptToMsgNew(ctOut)

		for i := 0; i < slots; i++ {
			delta := msg1.Value[i]*msg2.Value[i] - msgOut.Value[i]
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+12, math.Log2(math.Abs(real(delta))))
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+12, math.Log2(math.Abs(imag(delta))))
		}
	})
}
