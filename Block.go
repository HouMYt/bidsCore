package bids_core

import (
	"bytes"
	"io"
	"time"
)
const defaultTransactionAlloc = 2048
type Block struct {
	Header BlockHeader
	Transactions []*Tx
}
type BlockHeader struct {
	PrevHash ShaHash
	Timestamp time.Time
	MerkleRoot ShaHash
	RootSig RootSig
	AggSig AggSig
	Tag uint32
}
// AddTransaction adds a transaction to the message.
func (block *Block) AddTransaction(tx *Tx) error {
	block.Transactions = append(block.Transactions, tx)
	return nil

}

// ClearTransactions removes all transactions from the message.
func (block *Block) ClearTransactions() {
	block.Transactions = make([]*Tx, 0, defaultTransactionAlloc)
}
func (h *BlockHeader) BlockSha() ShaHash {
	// Encode the header and double sha256 everything prior to the number of
	// transactions.  Ignore the error returns since there is no way the
	// encode could fail except being out of memory which would cause a
	// run-time panic.
	var buf bytes.Buffer
	_ = writeBlockHeader(&buf,h)

	return DoubleSha256SH(buf.Bytes())
}
// writeBlockHeader writes a bitcoin block header to w.  See Serialize for
// encoding block headers to be stored to disk, such as in a database, as
// opposed to encoding for the wire.
func writeBlockHeader(w io.Writer, bh *BlockHeader) error {
	sec := uint32(bh.Timestamp.Unix())
	err := writeElements(w,&bh.PrevHash, &bh.MerkleRoot,&sec,&bh.RootSig,&bh.AggSig,&bh.Tag)
	if err != nil {
		return err
	}

	return nil
}
func readBlockHeader(r io.Reader, bh *BlockHeader) error {
	var sec uint32
	err := readElements(r,&bh.PrevHash, &bh.MerkleRoot,&sec,&bh.RootSig,&bh.AggSig,&bh.Tag)
	if err != nil {
		return err
	}
	bh.Timestamp = time.Unix(int64(sec), 0)

	return nil
}
func (h *BlockHeader) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of writeBlockHeader.
	return writeBlockHeader(w,h)
}
func (h *BlockHeader) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of readBlockHeader.
	return readBlockHeader(r,h)
}
func NewBlockHeader(prevHash *ShaHash,merkleRoot *ShaHash,rootSig RootSig,aggSig AggSig,tag uint32)*BlockHeader{
	return &BlockHeader{

		PrevHash: *prevHash,
		Timestamp: time.Unix(time.Now().Unix(), 0),
		MerkleRoot: *merkleRoot,
		RootSig: rootSig,
		AggSig: aggSig,
		Tag: tag,
	}
}
