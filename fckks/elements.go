package fckks

type Message struct {
	Value []complex128
}

func NewMessage(params Parameters) *Message {

	msg := new(Message)
	msg.Value = make([]complex128, params.Slots())

	return msg
}

func (msg *Message) Slots() int {
	return len(msg.Value)
}
