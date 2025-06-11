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

// Package containing helper structures and function
package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewBuffer(t *testing.T) {
	assert.Equal(t, []byte(nil), NewBuffer(nil).Bytes())
	assert.Equal(t, []byte{}, NewBuffer([]byte{}).Bytes())
	assert.Equal(t, []byte{1, 2, 3}, NewBuffer([]byte{1, 2, 3}).Bytes())
}

func TestBuffer_WriteReadUint8(t *testing.T) {
	b := NewBuffer(make([]byte, 0, 1))
	b.WriteUint8(0xff)
	assert.Equal(t, []byte{0xff}, b.Bytes())
	assert.Equal(t, byte(0xff), b.ReadUint8())
	assert.Equal(t, []byte{}, b.Bytes())
}

func TestBuffer_WriteReadUint64(t *testing.T) {
	b := NewBuffer(make([]byte, 0, 8))
	b.WriteUint64(0x1122334455667788)
	assert.Equal(t, []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}, b.Bytes())
	assert.Equal(t, uint64(0x1122334455667788), b.ReadUint64())
	assert.Equal(t, []byte{}, b.Bytes())
}

func TestBuffer_WriteReadUint64Slice(t *testing.T) {
	b := NewBuffer(make([]byte, 0, 8))
	b.WriteUint64Slice([]uint64{0x1122334455667788})
	assert.Equal(t, []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}, b.Bytes())
	s := make([]uint64, 1)
	b.ReadUint64Slice(s)
	assert.Equal(t, []uint64{0x1122334455667788}, s)
	assert.Equal(t, []byte{}, b.Bytes())
}
