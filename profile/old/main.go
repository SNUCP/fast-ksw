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
		0x7fbe40001, //0x7fbde0001,
		//0x7fbbe0001, //0x7fb960001,
		//0x7fb5e0001, 0x7fb580001,
	},
	P: []uint64{ // 36

		0xffff00001, 0xfff9c0001,
		0xfff8e0001, 0xfff840001,
		//0xfff700001, 0xfff640001,
		//0xfff4c0001, 0xfff3c0001,

		//0xfff280001, 0xfff100001,
		//0xffefe0001, 0xffee80001,
		//0xffee20001, 0xffeda0001,
		//0xffeca0001, 0xffea40001,

	},

	T: []uint64{ // 60
		0xffffffffffc0001, 0xfffffffff840001,
		0xfffffffff6a0001, 0xfffffffff5a0001,
		0xfffffffff2a0001, 0xfffffffff240001,
		0xffffffffefe0001, //0xffffffffeca0001,

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
	Gamma:        7,
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
