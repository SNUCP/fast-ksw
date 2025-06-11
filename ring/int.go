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
	"crypto/rand"
	"math/big"
)

// NewInt creates a new Int with a given int64 value.
func NewInt(v int64) *big.Int {
	return new(big.Int).SetInt64(v)
}

// NewUint creates a new Int with a given uint64 value.
func NewUint(v uint64) *big.Int {
	return new(big.Int).SetUint64(v)
}

// NewIntFromString creates a new Int from a string.
// A prefix of “0x” or “0X” selects base 16;
// the “0” prefix selects base 8, and
// a “0b” or “0B” prefix selects base 2.
// Otherwise, the selected base is 10.
func NewIntFromString(s string) *big.Int {
	i, _ := new(big.Int).SetString(s, 0)
	return i
}

// RandInt generates a random Int in [0, max-1].
func RandInt(max *big.Int) (n *big.Int) {
	var err error
	if n, err = rand.Int(rand.Reader, max); err != nil {
		panic("error: crypto/rand/bigint")
	}
	return
}

// DivRound sets the target i to round(a/b).
func DivRound(a, b, i *big.Int) {
	_a := new(big.Int).Set(a)
	i.Quo(_a, b)
	r := new(big.Int).Rem(_a, b)
	r2 := new(big.Int).Mul(r, NewInt(2))
	if r2.CmpAbs(b) != -1.0 {
		if _a.Sign() == b.Sign() {
			i.Add(i, NewInt(1))
		} else {
			i.Sub(i, NewInt(1))
		}
	}
}
