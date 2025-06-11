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

package ckks

import (
	"fast-ksw/rlwe"
)

// Decryptor is an interface wrapping a rlwe.Decryptor.
type Decryptor interface {
	DecryptNew(ciphertext *Ciphertext) (plaintext *Plaintext)
	Decrypt(ciphertext *Ciphertext, plaintext *Plaintext)
	ShallowCopy() Decryptor
	WithKey(sk *rlwe.SecretKey) Decryptor
}
type decryptor struct {
	rlwe.Decryptor
	params Parameters
}

// NewDecryptor instantiates a Decryptor for the CKKS scheme.
func NewDecryptor(params Parameters, sk *rlwe.SecretKey) Decryptor {
	return &decryptor{rlwe.NewDecryptor(params.Parameters, sk), params}
}

// Decrypt decrypts the ciphertext and write the result in ptOut.
func (dec *decryptor) DecryptNew(ciphertext *Ciphertext) (plaintext *Plaintext) {
	pt := NewPlaintext(dec.params, ciphertext.Level(), ciphertext.Scale)
	dec.Decryptor.Decrypt(ciphertext.Ciphertext, pt.Plaintext)
	return pt
}

// DecryptNew decrypts the ciphertext and returns the result in a newly allocated Plaintext.
func (dec *decryptor) Decrypt(ciphertext *Ciphertext, plaintext *Plaintext) {
	dec.Decryptor.Decrypt(&rlwe.Ciphertext{Value: ciphertext.Value}, &rlwe.Plaintext{Value: plaintext.Value})
	plaintext.Scale = ciphertext.Scale
}

// ShallowCopy creates a shallow copy of Decryptor in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// Decryptor can be used concurrently.
func (dec *decryptor) ShallowCopy() Decryptor {
	return &decryptor{dec.Decryptor.ShallowCopy(), dec.params}
}

// WithKey creates a shallow copy of Decryptor with a new decryption key, in which all the
// read-only data-structures are shared with the receiver and the temporary buffers
// are reallocated. The receiver and the returned Decryptor can be used concurrently.
func (dec *decryptor) WithKey(sk *rlwe.SecretKey) Decryptor {
	return &decryptor{dec.Decryptor.WithKey(sk), dec.params}
}
