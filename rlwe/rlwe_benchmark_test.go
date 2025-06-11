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

package rlwe

import (
	"encoding/json"
	"runtime"
	"testing"
)

func BenchmarkRLWE(b *testing.B) {
	defaultParams := TestParams
	if testing.Short() {
		defaultParams = TestParams[:2]
	}
	if *flagParamString != "" {
		var jsonParams ParametersLiteral
		json.Unmarshal([]byte(*flagParamString), &jsonParams)
		defaultParams = []ParametersLiteral{jsonParams} // the custom test suite reads the parameters from the -params flag
	}

	for _, defaultParam := range defaultParams {
		params, err := NewParametersFromLiteral(defaultParam)
		if err != nil {
			panic(err)
		}

		kgen := NewKeyGenerator(params)
		keySwitcher := NewKeySwitcher(params)

		for _, testSet := range []func(kgen KeyGenerator, keySwitcher *KeySwitcher, b *testing.B){
			benchHoistedKeySwitch,
		} {
			testSet(kgen, keySwitcher, b)
			runtime.GC()
		}
	}
}

func benchHoistedKeySwitch(kgen KeyGenerator, keySwitcher *KeySwitcher, b *testing.B) {

	params := kgen.(*keyGenerator).params
	skIn := kgen.GenSecretKey()
	skOut := kgen.GenSecretKey()
	plaintext := NewPlaintext(params, params.MaxLevel())
	plaintext.Value.IsNTT = true
	encryptor := NewEncryptor(params, skIn)
	ciphertext := NewCiphertextNTT(params, 1, plaintext.Level())
	encryptor.Encrypt(plaintext, ciphertext)

	swk := kgen.GenSwitchingKey(skIn, skOut)

	b.Run(testString(params, "DecomposeNTT/"), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			keySwitcher.DecomposeNTT(ciphertext.Level(), params.PCount()-1, params.PCount(), ciphertext.Value[1], keySwitcher.PoolDecompQP)
		}
	})

	b.Run(testString(params, "KeySwitchHoisted/"), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			keySwitcher.KeyswitchHoisted(ciphertext.Level(), keySwitcher.PoolDecompQP, swk, ciphertext.Value[0], ciphertext.Value[1], keySwitcher.Pool[1].P, keySwitcher.Pool[2].P)
		}
	})
}
