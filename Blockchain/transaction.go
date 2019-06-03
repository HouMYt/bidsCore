package Blockchain

import (
	"bytes"
	"io"
)

type Tx struct {
	Msg [datamsglehgth]byte
	Id  [idlength]byte
}

func (tx *Tx) TxSha() ShaHash {
	var buf bytes.Buffer
	tx.Serialize(&buf)
	return DoubleSha256SH(buf.Bytes())
}
func (tx *Tx) Serialize(writer io.Writer) error {
	return WriteElements(writer, tx.Msg, tx.Id)
}
func (tx *Tx)Deserialize(r io.Reader)error{
	return ReadElements(r,&tx.Msg,&tx.Id)
}
