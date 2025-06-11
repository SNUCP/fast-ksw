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
	"math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// test vectors for function DivRound
type argDivRound struct {
	x, y, want *big.Int
}

var divRoundVec = []argDivRound{
	{NewInt(0), NewInt(1), NewInt(0)},
	{NewInt(1), NewInt(2), NewInt(1)},
	{NewInt(5), NewInt(2), NewInt(3)},
	{NewInt(5), NewInt(3), NewInt(2)},
	{NewInt(5), NewInt(-2), NewInt(-3)},
	{NewInt(-5), NewInt(2), NewInt(-3)},
	{NewInt(-5), NewInt(-2), NewInt(3)},
	{NewInt(987654321), NewInt(123456789), NewInt(8)},
	{NewInt(-987654320), NewInt(123456789), NewInt(-8)},
	{NewInt(-121932631112635269), NewInt(-987654321), NewInt(123456789)},
	{NewIntFromString("123456789123456789123456789123456789"), NewInt(123456789), NewIntFromString("1000000001000000001000000001")},
	{NewIntFromString("987654321987654321987654321987654321"), NewIntFromString("123456789123456789123456789123456789"), NewInt(8)},
	{NewIntFromString("-987654321987654321987654321987654321"), NewIntFromString("-123456789123456789123456789123456789"), NewInt(8)},
}

func TestDivRound(t *testing.T) {
	z := new(big.Int)
	for i, testPair := range divRoundVec {
		DivRound(testPair.x, testPair.y, z)
		require.Zerof(t, z.Cmp(testPair.want), "Error DivRound test pair %v", i)
	}
}

func BenchmarkDivRound(b *testing.B) {
	z := new(big.Int)
	x := NewIntFromString("123456789123456789123456789123456789")
	y := NewIntFromString("987654321987654321987654321987654321")
	for i := 0; i < b.N; i++ {
		DivRound(x, y, z)
	}
}

func BenchmarkDivRoundDebug(b *testing.B) {
	y := int64(123456789)
	x := int64(987654321)
	for i := 0; i < b.N; i++ {
		x = int64(math.Round(float64(x / y)))
	}
}
