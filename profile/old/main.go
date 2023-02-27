package main

import (
	"fast-ksw/ckks"
	"fast-ksw/fckks"
	"fast-ksw/rlwe"
	"flag"
	"log"
	"os"
	"runtime/pprof"
)

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to `file`")
var memprofile = flag.String("memprofile", "", "write memory profile to `file`")

var PN16QP1760 = fckks.ParametersLiteral{
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

func main() {

	params := fckks.NewParametersFromLiteral(PN16QP1760)
	kgen := fckks.NewKeyGenerator(params)

	sk, pk := kgen.GenKeyPair()

	enc := fckks.NewEncryptor(params, pk)

	rlk := kgen.KeyGenerator.GenRelinearizationKey(sk, 1)
	eval := ckks.NewEvaluator(params.Parameters, rlwe.EvaluationKey{Rlk: rlk})

	msg := fckks.NewMessage(params)
	ct0 := enc.EncryptMsgNew(msg)

	ringQ := params.RingQ()
	ringQ.InvNTTLvl(ct0.Level(), ct0.Value[0], ct0.Value[0])
	ringQ.InvNTTLvl(ct0.Level(), ct0.Value[1], ct0.Value[1])
	ct0.Value[0].IsNTT = false
	ct0.Value[1].IsNTT = false

	flag.Parse()
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	// ... rest of the program ...
	for i := 0; i < 50; i++ {
		eval.SwitchKeysNew(ct0, rlk.Keys[0])
	}

}
