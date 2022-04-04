package fckks

import (
	"math"
	"testing"

	"fast-ksw/frlwe"

	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"github.com/tuneinsight/lattigo/v3/utils"

	"github.com/tuneinsight/lattigo/v3/ckks"

	"github.com/stretchr/testify/require"
)

var (
	PN15QP880 = ParametersLiteral{
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
			0x1ffffeca0001, 0x1ffffec30001,
		},
		P:            0x7fffffffe90001,                               // 55
		R:            []uint64{0xffffffffffc0001, 0xfffffffff840001}, // 60 x 2 bit
		Sigma:        rlwe.DefaultSigma,
		DefaultScale: 1 << 45,
		LogSlots:     14,
	}
)

type testContext struct {
	params Parameters
	ringQ  *ring.Ring
	kgen   *frlwe.KeyGenerator
	sk     *rlwe.SecretKey
	pk     *rlwe.PublicKey
	rlk    *frlwe.RelinKey
	enc    *Encryptor
	dec    *Decryptor
	eval   *Evaluator
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
	params := NewParametersFromLiteral(PN15QP880)
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
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+7, math.Log2(math.Abs(real(delta))))
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+7, math.Log2(math.Abs(imag(delta))))
		}
	})
}

func testEval(testctx *testContext, t *testing.T) {

	params := testctx.params
	slots := params.Slots()
	dec := testctx.dec
	eval := testctx.eval

	t.Run("Add", func(t *testing.T) {
		msg1, ct0 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))
		msg2, ct1 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))

		ctOut := eval.AddNew(ct0, ct1)

		msgOut := dec.DecryptToMsgNew(ctOut)

		for i := 0; i < slots; i++ {
			delta := msg1.Value[i] + msg2.Value[i] - msgOut.Value[i]
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+8, math.Log2(math.Abs(real(delta))))
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+8, math.Log2(math.Abs(imag(delta))))

		}
	})

	t.Run("MulAndRelin", func(t *testing.T) {
		msg1, ct0 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))
		msg2, ct1 := newTestVectors(testctx, complex(-1, -1), complex(1, 1))

		ctOut := eval.MulRelinNew(ct0, ct1, testctx.rlk)

		msgOut := dec.DecryptToMsgNew(ctOut)

		for i := 0; i < slots; i++ {
			delta := msg1.Value[i]*msg2.Value[i] - msgOut.Value[i]
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+12, math.Log2(math.Abs(real(delta))))
			require.GreaterOrEqual(t, -math.Log2(params.DefaultScale())+float64(params.LogSlots())+12, math.Log2(math.Abs(imag(delta))))
		}
	})
}
