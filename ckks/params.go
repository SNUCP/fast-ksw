package ckks

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"math/bits"

	"fast-ksw/ring"
	"fast-ksw/rlwe"
	"fast-ksw/utils"
)

var minLogSlots = 0

// Name of the different default parameter sets
var (

	// PN12QP109 is a default parameter set for logN=12 and logQP=109
	PN12QP109 = ParametersLiteral{
		LogN:     12,
		LogSlots: 11,
		Q: []uint64{0x200000e001, // 37 + 32
			0x100006001},
		P:            []uint64{0x3ffffea001}, // 38
		DefaultScale: 1 << 32,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.Standard,
	}

	// PN13QP218 is a default parameter set for logN=13 and logQP=218
	PN13QP218 = ParametersLiteral{
		LogN:     13,
		LogSlots: 12,
		Q: []uint64{0x1fffec001, // 33 + 5 x 30
			0x3fff4001,
			0x3ffe8001,
			0x40020001,
			0x40038001,
			0x3ffc0001},
		P:            []uint64{0x800004001}, // 35
		DefaultScale: 1 << 30,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.Standard,
	}
	// PN14QP438 is a default parameter set for logN=14 and logQP=438
	PN14QP438 = ParametersLiteral{
		LogN:     14,
		LogSlots: 13,
		Q: []uint64{0x200000008001, 0x400018001, // 45 + 9 x 34
			0x3fffd0001, 0x400060001,
			0x400068001, 0x3fff90001,
			0x400080001, 0x4000a8001,
			0x400108001, 0x3ffeb8001},
		P:            []uint64{0x7fffffd8001, 0x7fffffc8001}, // 43, 43
		DefaultScale: 1 << 34,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.Standard,
	}

	// PN15QP880 is a default parameter set for logN=15 and logQP=880
	PN15QP880 = ParametersLiteral{
		LogN:     15,
		LogSlots: 14,
		Q: []uint64{0x4000000120001, 0x10000140001, 0xffffe80001, // 50 + 17 x 40
			0x10000290001, 0xffffc40001, 0x100003e0001,
			0x10000470001, 0x100004b0001, 0xffffb20001,
			0x10000500001, 0x10000650001, 0xffff940001,
			0xffff8a0001, 0xffff820001, 0xffff780001,
			0x10000890001, 0xffff750001, 0x10000960001},
		P:            []uint64{0x40000001b0001, 0x3ffffffdf0001, 0x4000000270001}, // 50, 50, 50
		DefaultScale: 1 << 40,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.Standard,
	}
	// PN16QP1761 is a default parameter set for logN=16 and logQP = 1761
	PN16QP1761 = ParametersLiteral{
		LogN:     16,
		LogSlots: 15,
		Q: []uint64{0x80000000080001, 0x2000000a0001, 0x2000000e0001, 0x1fffffc20001, // 55 + 33 x 45
			0x200000440001, 0x200000500001, 0x200000620001, 0x1fffff980001,
			0x2000006a0001, 0x1fffff7e0001, 0x200000860001, 0x200000a60001,
			0x200000aa0001, 0x200000b20001, 0x200000c80001, 0x1fffff360001,
			0x200000e20001, 0x1fffff060001, 0x200000fe0001, 0x1ffffede0001,
			0x1ffffeca0001, 0x1ffffeb40001, 0x200001520001, 0x1ffffe760001,
			0x2000019a0001, 0x1ffffe640001, 0x200001a00001, 0x1ffffe520001,
			0x200001e80001, 0x1ffffe0c0001, 0x1ffffdee0001, 0x200002480001,
			0x1ffffdb60001, 0x200002560001},
		P:            []uint64{0x80000000440001, 0x7fffffffba0001, 0x80000000500001, 0x7fffffffaa0001}, // 4 x 55
		DefaultScale: 1 << 45,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.Standard,
	}

	// PN12QP109CI is a default parameter set for logN=12 and logQP=109
	PN12QP109CI = ParametersLiteral{
		LogN:     12,
		LogSlots: 12,
		Q: []uint64{0x1ffffe0001, // 37 + 32
			0x100014001},
		P:            []uint64{0x4000038001}, // 38
		DefaultScale: 1 << 32,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.ConjugateInvariant,
	}

	// PN13QP218CI is a default parameter set for logN=13 and logQP=218
	PN13QP218CI = ParametersLiteral{
		LogN:     13,
		LogSlots: 13,
		Q: []uint64{0x200038001, // 33 + 5 x 30
			0x3ffe8001,
			0x40020001,
			0x40038001,
			0x3ffc0001,
			0x40080001},
		P:            []uint64{0x800008001}, // 35
		DefaultScale: 1 << 30,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.ConjugateInvariant,
	}
	// PN14QP438CI is a default parameter set for logN=14 and logQP=438
	PN14QP438CI = ParametersLiteral{
		LogN:     14,
		LogSlots: 14,
		Q: []uint64{0x2000000a0001, 0x3fffd0001, // 45 + 9*34
			0x400060001, 0x3fff90001,
			0x400080001, 0x400180001,
			0x3ffd20001, 0x400300001,
			0x400360001, 0x4003e0001},
		P:            []uint64{0x80000050001, 0x7ffffdb0001}, // 43, 43
		DefaultScale: 1 << 34,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.ConjugateInvariant,
	}

	// PN15QP880CI is a default parameter set for logN=15 and logQP=880
	PN15QP880CI = ParametersLiteral{
		LogN:     15,
		LogSlots: 15,
		Q: []uint64{0x4000000120001, // 50 + 17 x 40
			0x10000140001, 0xffffe80001, 0xffffc40001,
			0x100003e0001, 0xffffb20001, 0x10000500001,
			0xffff940001, 0xffff8a0001, 0xffff820001,
			0xffff780001, 0x10000960001, 0x10000a40001,
			0xffff580001, 0x10000b60001, 0xffff480001,
			0xffff420001, 0xffff340001},
		P:            []uint64{0x3ffffffd20001, 0x4000000420001, 0x3ffffffb80001}, // 50, 50, 50
		DefaultScale: 1 << 40,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.ConjugateInvariant,
	}
	// PN16QP1761CI is a default parameter set for logN=16 and logQP = 1761
	PN16QP1761CI = ParametersLiteral{
		LogN:     16,
		LogSlots: 16,
		Q: []uint64{0x80000000080001, // 55 + 33 x 45
			0x200000440001, 0x200000500001, 0x1fffff980001, 0x200000c80001,
			0x1ffffeb40001, 0x1ffffe640001, 0x200001a00001, 0x200001e80001,
			0x1ffffe0c0001, 0x200002480001, 0x200002800001, 0x1ffffd800001,
			0x200002900001, 0x1ffffd700001, 0x2000029c0001, 0x1ffffcf00001,
			0x200003140001, 0x1ffffcc80001, 0x1ffffcb40001, 0x1ffffc980001,
			0x200003740001, 0x200003800001, 0x200003d40001, 0x1ffffc200001,
			0x1ffffc140001, 0x200004100001, 0x200004180001, 0x1ffffbc40001,
			0x200004700001, 0x1ffffb900001, 0x200004cc0001, 0x1ffffb240001,
			0x200004e80001},
		P:            []uint64{0x80000000440001, 0x80000000500001, 0x7fffffff380001, 0x80000000e00001}, // 4 x 55
		DefaultScale: 1 << 45,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.ConjugateInvariant,
	}

	// PN12QP101pq is a default (post quantum) parameter set for logN=12 and logQP=101
	PN12QP101pq = ParametersLiteral{
		LogN:         12,
		LogSlots:     11,
		Q:            []uint64{0x800004001, 0x40002001}, // 35 + 30
		P:            []uint64{0x1000002001},            // 36
		DefaultScale: 1 << 30,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.Standard,
	}
	// PN13QP202pq is a default (post quantum) parameter set for logN=13 and logQP=202
	PN13QP202pq = ParametersLiteral{
		LogN:         13,
		LogSlots:     12,
		Q:            []uint64{0x1fffec001, 0x8008001, 0x8020001, 0x802c001, 0x7fa8001, 0x7f74001}, // 33 + 5 x 27
		P:            []uint64{0x400018001},                                                        // 34
		DefaultScale: 1 << 27,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.Standard,
	}

	// PN14QP411pq is a default (post quantum) parameter set for logN=14 and logQP=411
	PN14QP411pq = ParametersLiteral{
		LogN:     14,
		LogSlots: 13,
		Q: []uint64{0x10000048001, 0x200038001, 0x1fff90001, 0x200080001, 0x1fff60001,
			0x2000b8001, 0x200100001, 0x1fff00001, 0x1ffef0001, 0x200128001}, // 40 + 9 x 33

		P:            []uint64{0x1ffffe0001, 0x1ffffc0001}, // 37, 37
		DefaultScale: 1 << 33,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.Standard,
	}

	// PN15QP827pq is a default (post quantum) parameter set for logN=15 and logQP=827
	PN15QP827pq = ParametersLiteral{
		LogN:     15,
		LogSlots: 14,
		Q: []uint64{0x400000060001, 0x4000170001, 0x3fffe80001, 0x40002f0001, 0x4000300001,
			0x3fffcf0001, 0x40003f0001, 0x3fffc10001, 0x4000450001, 0x3fffb80001,
			0x3fffb70001, 0x40004a0001, 0x3fffb20001, 0x4000510001, 0x3fffaf0001,
			0x4000540001, 0x4000560001, 0x4000590001}, // 46 + 17 x 38
		P:            []uint64{0x2000000a0001, 0x2000000e0001, 0x2000001d0001}, // 3 x 45
		DefaultScale: 1 << 38,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.Standard,
	}
	// PN16QP1654pq is a default (post quantum) parameter set for logN=16 and logQP=1654
	PN16QP1654pq = ParametersLiteral{LogN: 16,
		LogSlots: 15,
		Q: []uint64{0x80000000080001, 0x2000000a0001, 0x2000000e0001, 0x1fffffc20001, 0x200000440001,
			0x200000500001, 0x200000620001, 0x1fffff980001, 0x2000006a0001, 0x1fffff7e0001,
			0x200000860001, 0x200000a60001, 0x200000aa0001, 0x200000b20001, 0x200000c80001,
			0x1fffff360001, 0x200000e20001, 0x1fffff060001, 0x200000fe0001, 0x1ffffede0001,
			0x1ffffeca0001, 0x1ffffeb40001, 0x200001520001, 0x1ffffe760001, 0x2000019a0001,
			0x1ffffe640001, 0x200001a00001, 0x1ffffe520001, 0x200001e80001, 0x1ffffe0c0001,
			0x1ffffdee0001, 0x200002480001}, // 55 + 31 x 45
		P:            []uint64{0x7fffffffe0001, 0x80000001c0001, 0x80000002c0001, 0x7ffffffd20001}, // 4 x 51
		DefaultScale: 1 << 45,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.Standard,
	}

	// PN12QP101pq is a default (post quantum) parameter set for logN=12 and logQP=101
	PN12QP101CIpq = ParametersLiteral{
		LogN:         12,
		LogSlots:     12,
		Q:            []uint64{0x800004001, 0x3fff4001}, // 35 + 30
		P:            []uint64{0xffffc4001},             // 36
		DefaultScale: 1 << 30,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.ConjugateInvariant,
	}
	// PN13QP202CIpq is a default (post quantum) parameter set for logN=13 and logQP=202
	PN13QP202CIpq = ParametersLiteral{
		LogN:         13,
		LogSlots:     13,
		Q:            []uint64{0x1ffffe0001, 0x100050001, 0xfff88001, 0x100098001, 0x1000b0001}, // 37 + 4 x 32
		P:            []uint64{0x1ffffc0001},                                                    // 37
		DefaultScale: 1 << 32,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.ConjugateInvariant,
	}

	// PN14QP411CIpq is a default (post quantum) parameter set for logN=14 and logQP=411
	PN14QP411CIpq = ParametersLiteral{
		LogN:     14,
		LogSlots: 14,
		Q: []uint64{0x10000140001, 0x1fff90001, 0x200080001,
			0x1fff60001, 0x200100001, 0x1fff00001,
			0x1ffef0001, 0x1ffe60001, 0x2001d0001,
			0x2002e0001}, // 40 + 9 x 33

		P:            []uint64{0x1ffffe0001, 0x1ffffc0001}, // 37, 37
		DefaultScale: 1 << 33,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.ConjugateInvariant,
	}

	// PN15QP827CIpq is a default (post quantum) parameter set for logN=15 and logQP=827
	PN15QP827CIpq = ParametersLiteral{
		LogN:     15,
		LogSlots: 15,
		Q: []uint64{0x400000060001, 0x3fffe80001, 0x4000300001, 0x3fffb80001,
			0x40004a0001, 0x3fffb20001, 0x4000540001, 0x4000560001,
			0x3fff900001, 0x4000720001, 0x3fff8e0001, 0x4000800001,
			0x40008a0001, 0x3fff6c0001, 0x40009e0001, 0x3fff300001,
			0x3fff1c0001, 0x4000fc0001}, // 46 + 17 x 38
		P:            []uint64{0x2000000a0001, 0x2000000e0001, 0x1fffffc20001}, // 3 x 45
		DefaultScale: 1 << 38,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.ConjugateInvariant,
	}
	// PN16QP1654CIpq is a default (post quantum) parameter set for logN=16 and logQP=1654
	PN16QP1654CIpq = ParametersLiteral{LogN: 16,
		LogSlots: 16,
		Q: []uint64{0x80000000080001, 0x200000440001, 0x200000500001, 0x1fffff980001,
			0x200000c80001, 0x1ffffeb40001, 0x1ffffe640001, 0x200001a00001,
			0x200001e80001, 0x1ffffe0c0001, 0x200002480001, 0x200002800001,
			0x1ffffd800001, 0x200002900001, 0x1ffffd700001, 0x2000029c0001,
			0x1ffffcf00001, 0x200003140001, 0x1ffffcc80001, 0x1ffffcb40001,
			0x1ffffc980001, 0x200003740001, 0x200003800001, 0x200003d40001,
			0x1ffffc200001, 0x1ffffc140001, 0x200004100001, 0x200004180001,
			0x1ffffbc40001, 0x200004700001, 0x1ffffb900001, 0x200004cc0001}, // 55 + 31 x 45
		P:            []uint64{0x80000001c0001, 0x80000002c0001, 0x8000000500001, 0x7ffffff9c0001}, // 4 x 51
		DefaultScale: 1 << 45,
		Sigma:        rlwe.DefaultSigma,
		RingType:     ring.ConjugateInvariant,
	}
)

// ParametersLiteral is a literal representation of BFV parameters.  It has public
// fields and is used to express unchecked user-defined parameters literally into
// Go programs. The NewParametersFromLiteral function is used to generate the actual
// checked parameters from the literal representation.
//
// Users must set the polynomial degree (in log_2, LogN) and the coefficient modulus, by either setting
// the Q and P fields to the desired moduli chain, or by setting the LogQ and LogP fields to
// the desired moduli sizes (in log_2). Users must also specify a default initial scale for the plaintexts.
//
// Optionally, users may specify the error variance (Sigma), the secrets' density (H), the ring
// type (RingType) and the number of slots (in log_2, LogSlots). If left unset, standard default values for
// these field are substituted at parameter creation (see NewParametersFromLiteral).
type ParametersLiteral struct {
	LogN         int // Ring degree (power of 2)
	Q            []uint64
	P            []uint64
	LogQ         []int `json:",omitempty"`
	LogP         []int `json:",omitempty"`
	H            int
	Sigma        float64 // Gaussian sampling variance
	LogSlots     int
	DefaultScale float64
	RingType     ring.Type
}

// DefaultParams is a set of default CKKS parameters ensuring 128 bit security in a classic setting.
var DefaultParams = []ParametersLiteral{PN12QP109, PN13QP218, PN14QP438, PN15QP880, PN16QP1761}

// DefaultConjugateInvariantParams is a set of default conjugate invariant parameters for encrypting real values and ensuring 128 bit security in a classic setting.
var DefaultConjugateInvariantParams = []ParametersLiteral{PN12QP109CI, PN13QP218CI, PN14QP438CI, PN15QP880CI, PN16QP1761CI}

// DefaultPostQuantumParams is a set of default CKKS parameters ensuring 128 bit security in a post-quantum setting.
var DefaultPostQuantumParams = []ParametersLiteral{PN12QP101pq, PN13QP202pq, PN14QP411pq, PN15QP827pq, PN16QP1654pq}

// DefaultPostQuantumConjugateInvariantParams is a set of default conjugate invariant parameters for encrypting real values and ensuring 128 bit security in a post-quantum setting.
var DefaultPostQuantumConjugateInvariantParams = []ParametersLiteral{PN12QP101CIpq, PN13QP202CIpq, PN14QP411CIpq, PN15QP827CIpq, PN16QP1654CIpq}

// Parameters represents a parameter set for the CKKS cryptosystem. Its fields are private and
// immutable. See ParametersLiteral for user-specified parameters.
type Parameters struct {
	rlwe.Parameters

	logSlots     int
	defaultScale float64
}

// NewParameters instantiate a set of CKKS parameters from the generic RLWE parameters and the CKKS-specific ones.
// It returns the empty parameters Parameters{} and a non-nil error if the specified parameters are invalid.
func NewParameters(rlweParams rlwe.Parameters, logSlots int, defaultScale float64) (p Parameters, err error) {
	if rlweParams.Equals(rlwe.Parameters{}) {
		return Parameters{}, fmt.Errorf("provided RLWE parameters are invalid")
	}

	if maxLogSlots := bits.Len64(rlweParams.RingQ().NthRoot) - 3; logSlots > maxLogSlots || logSlots < minLogSlots {
		return Parameters{}, fmt.Errorf("logSlot=%d is larger than the logN-1=%d or smaller than %d", logSlots, maxLogSlots, minLogSlots)
	}

	return Parameters{rlweParams, logSlots, defaultScale}, nil
}

// NewParametersFromLiteral instantiate a set of CKKS parameters from a ParametersLiteral specification.
// It returns the empty parameters Parameters{} and a non-nil error if the specified parameters are invalid.
//
// If the `LogSlots` field is left unset, its value is set to `LogN-1` for the Standard ring and to `LogN` for
// the conjugate-invariant ring.
//
// See `rlwe.NewParametersFromLiteral` for default values of the other optional fields.
func NewParametersFromLiteral(pl ParametersLiteral) (Parameters, error) {
	rlweParams, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{LogN: pl.LogN, Q: pl.Q, P: pl.P, LogQ: pl.LogQ, LogP: pl.LogP, H: pl.H, Sigma: pl.Sigma, RingType: pl.RingType})
	if err != nil {
		return Parameters{}, err
	}

	if pl.LogSlots == 0 {
		switch pl.RingType {
		case ring.Standard:
			pl.LogSlots = pl.LogN - 1
		case ring.ConjugateInvariant:
			pl.LogSlots = pl.LogN
		}
	}

	return NewParameters(rlweParams, pl.LogSlots, pl.DefaultScale)
}

// StandardParameters returns the CKKS parameters corresponding to the receiver
// parameter set. If the receiver is already a standard parameter set
// (i.e., RingType==Standard), then the method returns the receiver.
func (p Parameters) StandardParameters() (pckks Parameters, err error) {
	if p.RingType() == ring.Standard {
		return p, nil
	}
	pckks = p
	pckks.Parameters, err = pckks.Parameters.StandardParameters()
	return
}

// LogSlots returns the log of the number of slots
func (p Parameters) LogSlots() int {
	return p.logSlots
}

// MaxLevel returns the maximum ciphertext level
func (p Parameters) MaxLevel() int {
	return p.QCount() - 1
}

// Slots returns number of available plaintext slots
func (p Parameters) Slots() int {
	return 1 << p.logSlots
}

// MaxSlots returns the theoretical maximum of plaintext slots allowed by the ring degree
func (p Parameters) MaxSlots() int {
	switch p.RingType() {
	case ring.Standard:
		return p.N() >> 1
	case ring.ConjugateInvariant:
		return p.N()
	default:
		panic("invalid ring type")
	}
}

// MaxLogSlots returns the log of the maximum number of slots enabled by the parameters
func (p Parameters) MaxLogSlots() int {
	switch p.RingType() {
	case ring.Standard:
		return p.LogN() - 1
	case ring.ConjugateInvariant:
		return p.LogN()
	default:
		panic("invalid ring type")
	}
}

// DefaultScale returns the default plaintext/ciphertext scale
func (p Parameters) DefaultScale() float64 {
	return p.defaultScale
}

// LogQLvl returns the size of the modulus Q in bits at a specific level
func (p Parameters) LogQLvl(level int) int {
	tmp := p.QLvl(level)
	return tmp.BitLen()
}

// QLvl returns the product of the moduli at the given level as a big.Int
func (p Parameters) QLvl(level int) *big.Int {
	tmp := ring.NewUint(1)
	for _, qi := range p.Q()[:level+1] {
		tmp.Mul(tmp, ring.NewUint(qi))
	}
	return tmp
}

// RotationsForInnerSum generates the rotations that will be performed by the
// `Evaluator.InnerSum` operation when performed with parameters `batch` and `n`.
func (p Parameters) RotationsForInnerSum(batch, n int) (rotations []int) {
	rotations = []int{}
	for i := 1; i < n; i++ {
		rotations = append(rotations, i*batch)
	}
	return
}

// RotationsForInnerSumLog generates the rotations that will be performed by the
// `Evaluator.InnerSumLog` operation when performed with parameters `batch` and `n`.
func (p Parameters) RotationsForInnerSumLog(batch, n int) (rotations []int) {

	rotIndex := make(map[int]bool)

	rotations = []int{}
	var k int
	for i := 1; i < n; i <<= 1 {

		k = i
		k *= batch
		rotIndex[k] = true

		k = n - (n & ((i << 1) - 1))
		k *= batch
		rotIndex[k] = true
	}

	rotations = make([]int, len(rotIndex))
	var i int
	for j := range rotIndex {
		rotations[i] = j
		i++
	}

	return
}

// RotationsForReplicate generates the rotations that will be performed by the
// `Evaluator.Replicate` operation when performed with parameters `batch` and `n`.
func (p Parameters) RotationsForReplicate(batch, n int) (rotations []int) {
	return p.RotationsForInnerSum(-batch, n)
}

// RotationsForReplicateLog generates the rotations that will be performed by the
// `Evaluator.ReplicateLog` operation when performed with parameters `batch` and `n`.
func (p Parameters) RotationsForReplicateLog(batch, n int) (rotations []int) {
	return p.RotationsForInnerSumLog(-batch, n)
}

// RotationsForTrace generates the rotations that will be performed by the
// `Evaluator.SubSum` operation.
func (p Parameters) RotationsForTrace(logSlotsStart, logSlotsEnd int) (rotations []int) {
	rotations = []int{}
	//SubSum rotation needed X -> Y^slots rotations
	for i := logSlotsStart; i < logSlotsEnd; i++ {
		rotations = append(rotations, 1<<i)
	}

	return
}

// Equals compares two sets of parameters for equality.
func (p Parameters) Equals(other Parameters) bool {
	res := p.Parameters.Equals(other.Parameters)
	res = res && (p.logSlots == other.LogSlots())
	res = res && (p.defaultScale == other.DefaultScale())
	return res
}

// CopyNew makes a deep copy of the receiver and returns it.
//
// Deprecated: Parameter is now a read-only struct, except for the UnmarshalBinary method: deep copying should only be
// required to save a Parameter struct before calling its UnmarshalBinary method and it will be deprecated when
// transitioning to a immutable serialization interface.
func (p Parameters) CopyNew() Parameters {
	p.Parameters = p.Parameters.CopyNew()
	return p
}

// MarshalBinary returns a []byte representation of the parameter set.
func (p Parameters) MarshalBinary() ([]byte, error) {
	if p.LogN() == 0 { // if N is 0, then p is the zero value
		return []byte{}, nil
	}

	rlweBytes, err := p.Parameters.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// len(rlweBytes) : RLWE parameters
	// 1 byte : logSlots
	// 8 byte : defaultScale
	b := utils.NewBuffer(make([]byte, 0, p.MarshalBinarySize()))
	b.WriteUint8Slice(rlweBytes)
	b.WriteUint8(uint8(p.logSlots))
	b.WriteUint64(math.Float64bits(p.defaultScale))
	return b.Bytes(), nil
}

// UnmarshalBinary decodes a []byte into a parameter set struct
func (p *Parameters) UnmarshalBinary(data []byte) (err error) {
	var rlweParams rlwe.Parameters
	if err := rlweParams.UnmarshalBinary(data); err != nil {
		return err
	}
	logSlots := int(data[len(data)-9])
	scale := math.Float64frombits(binary.BigEndian.Uint64(data[len(data)-8:]))
	*p, err = NewParameters(rlweParams, logSlots, scale)
	return err
}

// MarshalBinarySize returns the length of the []byte encoding of the receiver.
func (p Parameters) MarshalBinarySize() int {
	return p.Parameters.MarshalBinarySize() + 9
}

// MarshalJSON returns a JSON representation of this parameter set. See `Marshal` from the `encoding/json` package.
func (p Parameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(ParametersLiteral{LogN: p.LogN(), Q: p.Q(), P: p.P(), H: p.HammingWeight(), Sigma: p.Sigma(), LogSlots: p.logSlots, DefaultScale: p.defaultScale, RingType: p.RingType()})
}

// UnmarshalJSON reads a JSON representation of a parameter set into the receiver Parameter. See `Unmarshal` from the `encoding/json` package.
func (p *Parameters) UnmarshalJSON(data []byte) (err error) {
	var params ParametersLiteral
	json.Unmarshal(data, &params)
	*p, err = NewParametersFromLiteral(params)
	return
}
