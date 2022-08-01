package fckks

import (
	"fast-ksw/ckks"
	"fast-ksw/rlwe"
)

type Encryptor struct {
	ckks.Encryptor
	params   Parameters
	encoder  ckks.Encoder
	ptxtPool *ckks.Plaintext
}

func NewEncryptor(params Parameters, pk *rlwe.PublicKey) (enc *Encryptor) {
	enc = new(Encryptor)
	enc.params = params
	enc.ptxtPool = ckks.NewPlaintext(params.Parameters, params.MaxLevel(), params.DefaultScale())
	enc.Encryptor = ckks.NewEncryptor(params.Parameters, pk)
	enc.encoder = ckks.NewEncoder(params.Parameters)

	return
}

func (enc *Encryptor) Encrypt(ptxtIn *ckks.Plaintext, ctxtOut *ckks.Ciphertext) {
	enc.Encryptor.Encrypt(ptxtIn, ctxtOut)
}

func (enc *Encryptor) EncryptMsg(msg *Message, ctOut *ckks.Ciphertext) {
	enc.encoder.Encode(msg.Value, enc.ptxtPool, enc.params.LogSlots())
	enc.Encrypt(enc.ptxtPool, ctOut)
}

// EncryptMsg encode message and then encrypts the input plaintext and write the result on ctOut. The encryption
// algorithm depends on how the receiver encryptor was initialized (see NewEncryptor
// and NewFastEncryptor).
// The level of the output ciphertext is min(plaintext.Level(), ciphertext.Level()).
func (enc *Encryptor) EncryptMsgNew(msg *Message) (ctOut *ckks.Ciphertext) {

	ctOut = ckks.NewCiphertext(enc.params.Parameters, 1, enc.params.MaxLevel(), enc.params.DefaultScale())
	enc.EncryptMsg(msg, ctOut)

	return
}
