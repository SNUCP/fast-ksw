package fckks

import (
	"github.com/tuneinsight/lattigo/v3/ckks"
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

type Decryptor struct {
	ckks.Decryptor
	params   Parameters
	encoder  ckks.Encoder
	ptxtPool *ckks.Plaintext
}

func NewDecryptor(params Parameters, sk *rlwe.SecretKey) (dec *Decryptor) {
	dec = new(Decryptor)
	dec.params = params
	dec.ptxtPool = ckks.NewPlaintext(params.Parameters, params.MaxLevel(), params.DefaultScale())
	dec.Decryptor = ckks.NewDecryptor(params.Parameters, sk)
	dec.encoder = ckks.NewEncoder(params.Parameters)

	return
}

func (dec *Decryptor) Decrypt(ctIn *ckks.Ciphertext, ptOut *ckks.Plaintext) {
	dec.Decryptor.Decrypt(ctIn, ptOut)
}

func (dec *Decryptor) DecryptToMsg(ctIn *ckks.Ciphertext, msgOut *Message) {
	dec.Decrypt(ctIn, dec.ptxtPool)
	msgOut.Value = dec.encoder.Decode(dec.ptxtPool, dec.params.LogSlots())
}

func (dec *Decryptor) DecryptToMsgNew(ctIn *ckks.Ciphertext) (msgOut *Message) {
	msgOut = NewMessage(dec.params)
	dec.DecryptToMsg(ctIn, msgOut)
	return
}
