package bids_core

type Tx struct {
	msg []byte
	id  []byte
}

func (tx *Tx) TxSha() ShaHash {

	return DoubleSha256SH(tx.Serialize())
}
func (tx *Tx)Serialize() []byte {
	return append(tx.msg,tx.id...)
}
