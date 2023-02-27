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
		Q: []uint64{ // 36 x 24

			0xffff00001, 0xfff9c0001, 0xfff8e0001, 0xfff840001,
			0xfff700001, 0xfff640001, 0xfff4c0001, 0xfff3c0001,
			0xfff280001, 0xfff100001, 0xffefe0001, 0xffee80001,

			0x10004a0001, 0x1000500001, 0x1000960001, 0x1000a20001,
			0x1000b40001, 0x1000f60001, 0x10011a0001, 0x1001220001,
			0x10014c0001, 0x1001680001, 0x10017c0001, //0x1001880001,

		},

		P: []uint64{ // 36 x 4
			0x1002700001, //0x1002720001, 0x1002c00001, 0x1002e40001,
		},

		T: []uint64{ // 60 x 8
			0xffffffffffc0001, 0xfffffffff840001,
			0xfffffffff6a0001, //0xfffffffff5a0001,
			//0xfffffffff2a0001, 0xfffffffff240001,
			//0xffffffffefe0001, 0xffffffffeca0001,
		},

		Sigma:        rlwe.DefaultSigma,
		DefaultScale: 1 << 36,
		LogSlots:     14,
		Gamma:        3,
		// len(P) stands for r, len(T) stands for r', gamma stands for tilde_r

	}

	PN16QP1760 = ParametersLiteral{
		LogN: 16,
		Q: []uint64{ // 36 x 48

			0xffff00001, 0xfff9c0001, 0xfff8e0001, 0xfff840001,
			0xfff700001, 0xfff640001, 0xfff4c0001, 0xfff3c0001,
			0xfff280001, 0xfff100001, 0xffefe0001, 0xffee80001,

			0x10004a0001, 0x1000500001, 0x1000960001, 0x1000a20001,
			0x1000b40001, 0x1000f60001, 0x10011a0001, 0x1001220001,
			0x10014c0001, 0x1001680001, 0x10017c0001, 0x1001880001,

			0xffee20001, 0xffeda0001, 0xffeca0001, 0xffea40001,
			0xffe940001, 0xffe920001, 0xffe760001, 0xffe040001,
			0xffdf80001, 0xffdf00001, 0xffdd20001, 0xffdbc0001,

			0x1001940001, 0x1001a40001, 0x1001d00001, 0x1001fa0001,
			0x1002180001, 0x10021c0001, 0x10021e0001, 0x1002300001,
			0x1002340001, 0x1002480001, 0x1002540001, //0x10025a0001,
		},
		P: []uint64{ // 36 x 4
			0x1002700001, //0x1002720001, 0x1002c00001, 0x1002e40001,
		},

		T: []uint64{ // 60 x 8
			0xffffffffffc0001, 0xfffffffff840001,
			0xfffffffff6a0001, 0xfffffffff5a0001,
			//0xfffffffff2a0001, 0xfffffffff240001,
			//0xffffffffefe0001, 0xffffffffeca0001,
		},

		Sigma:        rlwe.DefaultSigma,
		DefaultScale: 1 << 36,
		LogSlots:     15,
		Gamma:        5,
		// 1:3:3 2:4:4 4:5:6 6:7:9 8:8:10 10:9:12
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

	testctx.kgen = NewKeyGenerator(testctx.params)

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

	paramList := []ParametersLiteral{PN15QP870, PN16QP1760}

	for _, paramsLiteral := range paramList {
		params := NewParametersFromLiteral(paramsLiteral)
		testctx, err := genTestParams(params)
		if err != nil {
			panic(err)
		}

		testEncrypt(testctx, t)
		testEval(testctx, t)
	}

}

func testEncrypt(testctx *testContext, t *testing.T) {

	params := testctx.params
	slots := params.Slots()
	dec := testctx.dec

	t.Run("Encrypt & Decrypt", func(t *testing.T) {
		msg, ctxt := newTestVectors(testctx, complex(-0.5, -0.5), complex(0.5, 0.5))
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
		msg1, ct0 := newTestVectors(testctx, complex(-0.5, -0.5), complex(0.5, 0.5))
		msg2, ct1 := newTestVectors(testctx, complex(-0.5, -0.5), complex(0.5, 0.5))

		ctOut := eval.AddNew(ct0, ct1)

		msgOut := dec.DecryptToMsgNew(ctOut)

		for i := 0; i < slots; i++ {
			delta := msg1.Value[i] + msg2.Value[i] - msgOut.Value[i]
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+9, math.Log2(math.Abs(real(delta))))
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+9, math.Log2(math.Abs(imag(delta))))

		}
	})

	t.Run("MulAndRelinOld", func(t *testing.T) {
		msg1, ct0 := newTestVectors(testctx, complex(-0.5, -0.5), complex(0.5, 0.5))
		msg2, ct1 := newTestVectors(testctx, complex(-0.5, -0.5), complex(0.5, 0.5))

		ctOut := evalOld.MulRelinNew(ct0, ct1)

		require.Equal(t, ctOut.Degree(), 1)

		msgOut := dec.DecryptToMsgNew(ctOut)

		for i := 0; i < slots; i++ {
			delta := msg1.Value[i]*msg2.Value[i] - msgOut.Value[i]
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+12, math.Log2(math.Abs(real(delta))))
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+12, math.Log2(math.Abs(imag(delta))))
		}
	})

	t.Run("MulAndRelin", func(t *testing.T) {
		msg1, ct0 := newTestVectors(testctx, complex(-0.5, -0.5), complex(0.5, 0.5))
		msg2, ct1 := newTestVectors(testctx, complex(-0.5, -0.5), complex(0.5, 0.5))

		ctOut := eval.MulRelinNew(ct0, ct1, testctx.rlk)

		require.Equal(t, ctOut.Degree(), 1)

		msgOut := dec.DecryptToMsgNew(ctOut)

		for i := 0; i < slots; i++ {
			delta := msg1.Value[i]*msg2.Value[i] - msgOut.Value[i]
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+12, math.Log2(math.Abs(real(delta))))
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+12, math.Log2(math.Abs(imag(delta))))
		}
	})

}
