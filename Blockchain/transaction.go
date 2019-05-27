package Blockchain

import (
	"bytes"
	"io"
)

type Tx struct {
	msg [datamsglehgth]byte
	id  [idlength]byte
}

func (tx *Tx) TxSha() ShaHash {
	var buf bytes.Buffer
	tx.Serialize(&buf)
	return DoubleSha256SH(buf.Bytes())
}
func (tx *Tx) Serialize(writer io.Writer) error {
	return WriteElements(writer, tx.msg, tx.id)
}
func (tx *Tx)Deserialize(r io.Reader)error{
	return ReadElements(r,&tx.msg,&tx.id)
}
