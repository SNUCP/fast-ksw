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

package ring

import (
	"fast-ksw/utils"
)

// UnfoldConjugateInvariantToStandard maps the compressed representation (N/2 coefficients)
// of Z_Q[X+X^-1]/(X^2N + 1) to full representation in Z_Q[X]/(X^2N+1).
// Requires degree(polyConjugateInvariant) = 2*degree(polyStd).
// Requires that polyStd and polyConjugateInvariant share the same moduli.
func (r *Ring) UnfoldConjugateInvariantToStandard(level int, polyConjugateInvariant, polyStd *Poly) {

	if 2*len(polyConjugateInvariant.Coeffs[0]) != len(polyStd.Coeffs[0]) {
		panic("Ring degree of polyConjugateInvariant must be twice the ring degree of polyStd")
	}

	N := len(polyConjugateInvariant.Coeffs[0])

	for i := 0; i < level+1; i++ {
		tmp2, tmp1 := polyStd.Coeffs[i], polyConjugateInvariant.Coeffs[i]
		copy(tmp2, tmp1)
		for idx, jdx := N-1, N; jdx < 2*N; idx, jdx = idx-1, jdx+1 {
			tmp2[jdx] = tmp1[idx]
		}
	}
}

// FoldStandardToConjugateInvariant folds [X]/(X^N+1) to [X+X^-1]/(X^N+1) in compressed form (N/2 coefficients).
// Requires degree(polyConjugateInvariant) = 2*degree(polyStd).
// Requires that polyStd and polyConjugateInvariant share the same moduli.
func (r *Ring) FoldStandardToConjugateInvariant(level int, polyStandard *Poly, permuteNTTIndexInv []uint64, polyConjugateInvariant *Poly) {

	if len(polyStandard.Coeffs[0]) != 2*len(polyConjugateInvariant.Coeffs[0]) {
		panic("Ring degree of p2 must be 2N and ring degree of p1 must be N")
	}

	r.PermuteNTTWithIndexLvl(level, polyStandard, permuteNTTIndexInv, polyConjugateInvariant)
	for i := 0; i < level+1; i++ {
		AddVec(polyConjugateInvariant.Coeffs[i][:r.N], polyStandard.Coeffs[i][:r.N], polyConjugateInvariant.Coeffs[i][:r.N], r.Modulus[i])
	}
}

// PadDefaultRingToConjuateInvariant converts a polynomial in Z[X]/(X^N +1) to a polynomial in Z[X+X^-1]/(X^2N+1).
// Conversion will check the .IsNTT flag of the polynomial p1.
func PadDefaultRingToConjuateInvariant(p1 *Poly, ringQ *Ring, p2 *Poly) {

	if p1 == p2 {
		panic("p1 == p2 but method cannot be used in place")
	}

	level := utils.MinInt(p1.Level(), p2.Level())
	n := len(p1.Coeffs[0])

	for i := 0; i < level+1; i++ {
		qi := ringQ.Modulus[i]

		if len(p2.Coeffs[i]) != 2*len(p1.Coeffs[i]) {
			panic("p2 degree must be twice the one of p1")
		}

		copy(p2.Coeffs[i], p1.Coeffs[i])

		tmp := p2.Coeffs[i]
		if p1.IsNTT {
			for j := 0; j < n; j++ {
				tmp[n-j-1] = tmp[j]
			}
		} else {
			tmp[0] = 0
			for j := 1; j < n; j++ {
				tmp[n-j] = qi - tmp[j]
			}
		}
	}

	p2.IsNTT = p1.IsNTT
}
