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
		Q: []uint64{ // 40 + 35
			0xffff340001,

			0x7fff80001, 0x7ffd80001,
			0x7ffc80001, 0x7ff9c0001,
			0x7ff900001, 0x7ff860001,
			0x7ff6c0001, 0x7ff300001,

			0x7ff120001, 0x7fef40001,
			0x7feea0001, 0x7fed80001,
			0x7febe0001, 0x7feae0001,
			0x7feac0001, 0x7fe960001,

			0x7fe820001, 0x7fe780001,
			0x7fe5a0001, 0x7fe540001,
			0x7fe220001, 0x7fdee0001,
			0x7fde20001, //0x7fddc0001,

		},

		P: []uint64{ // 36

			0xffff00001, //0xfff9c0001,
			//0xfff8e0001, 0xfff840001,
			//0xfff700001, 0xfff640001,
			//0xfff4c0001, 0xfff3c0001,

			//0xfff280001, 0xfff100001,
			//0xffefe0001, 0xffee80001,
			//0xffee20001, 0xffeda0001,
			//0xffeca0001, 0xffea40001,
		},

		T: []uint64{ // 60
			0xffffffffffc0001, 0xfffffffff840001,
			0xfffffffff6a0001, //0xfffffffff5a0001,
			//0xfffffffff2a0001, 0xfffffffff240001,
			//0xffffffffefe0001, 0xffffffffeca0001,
			//0xffffffffe9e0001, 0xffffffffe7c0001,
			//0xffffffffe740001, 0xffffffffe520001,
		},

		Sigma:        rlwe.DefaultSigma,
		DefaultScale: 1 << 35,
		LogSlots:     14,
		Gamma:        3,
		//1:3:3  2:4:4  4:5:6  6:6:8  8:8:10

	}

	PN16QP1760 = ParametersLiteral{
		LogN: 16,
		Q: []uint64{ // 40 + 35 x 48

			0xffff340001,

			0x7fff80001, 0x7ffd80001,
			0x7ffc80001, 0x7ff9c0001,
			0x7ff900001, 0x7ff860001,
			0x7ff6c0001, 0x7ff300001,

			0x7ff120001, 0x7fef40001,
			0x7feea0001, 0x7fed80001,
			0x7febe0001, 0x7feae0001,
			0x7feac0001, 0x7fe960001,

			0x7fe820001, 0x7fe780001,
			0x7fe5a0001, 0x7fe540001,
			0x7fe220001, 0x7fdee0001,
			0x7fde20001, 0x7fddc0001,

			0x7fdc80001, 0x7fd8e0001,
			0x7fd6e0001, 0x7fd580001,
			0x7fd520001, 0x7fd3a0001,
			0x7fcf20001, 0x7fce40001,

			0x7fcd40001, 0x7fccc0001,
			0x7fcc20001, 0x7fcae0001,
			0x7fca80001, 0x7fc8a0001,
			0x7fc680001, 0x7fc620001,

			0x7fc600001, 0x7fc060001,
			0x7fbe40001, 0x7fbde0001,
			0x7fbbe0001, 0x7fb960001,
			0x7fb5e0001, //0x7fb580001,
		},
		P: []uint64{ // 36

			0xffff00001, //0xfff9c0001,
			//0xfff8e0001, 0xfff840001,
			//0xfff700001, 0xfff640001,
			//0xfff4c0001, 0xfff3c0001,

			//0xfff280001, 0xfff100001,
			//0xffefe0001, 0xffee80001,
			//0xffee20001, 0xffeda0001,
			//0xffeca0001, 0xffea40001,

		},

		T: []uint64{ // 60
			0xffffffffffc0001, 0xfffffffff840001,
			0xfffffffff6a0001, //0xfffffffff5a0001,
			//0xfffffffff2a0001, 0xfffffffff240001,
			//0xffffffffefe0001, 0xffffffffeca0001,

			//0xffffffffe9e0001, 0xffffffffe7c0001,
			//0xffffffffe740001, 0xffffffffe520001,
			//0xffffffffe4c0001, 0xffffffffe440001,
			//0xffffffffe400001, 0xffffffffdda0001,

			//0xffffffffdd20001, 0xffffffffdbc0001,
			//0xffffffffdb60001, 0xffffffffd8a0001,
		},

		Sigma:        rlwe.DefaultSigma,
		DefaultScale: 1 << 35,
		LogSlots:     15,
		Gamma:        3,
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
	params := NewParametersFromLiteral(PN15QP870)
	testctx, err := genTestParams(params)
	if err != nil {
		panic(err)
	}

	testEncrypt(testctx, t)
	//testEval(testctx, t)
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

}
