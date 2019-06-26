package Blockchain

import (
	aggSig_pkg "bids_core/aggSig"
	"bytes"
	"errors"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/fastsha256"
	"io"
	"time"
)

const defaultTransactionAlloc = 2048
const datamsglehgth = 1024
const idlength = 4

type Block struct {
	Header       *BlockHeader
	Transactions []Tx
}
type BlockHeader struct {
	PrevHash   ShaHash
	Timestamp  time.Time
	MerkleRoot ShaHash
	RootSig    NodeSig
	AggSig     AggSig
	Tag        uint32
}
type DataMsg struct {
	Id  [idlength]byte
	Msg [datamsglehgth]byte
	Sig SensorSig
}

// AddTransaction adds a transaction to the message.
func (block *Block) AddTransaction(tx Tx) {
	block.Transactions = append(block.Transactions, tx)

}

// ClearTransactions removes all transactions from the message.
func (block *Block) ClearTransactions() {
	block.Transactions = make([]Tx, 0, defaultTransactionAlloc)
}
func (h *BlockHeader) BlockSha() ShaHash {
	// Encode the header and double sha256 everything prior to the number of
	// transactions.  Ignore the error returns since there is no way the
	// encode could fail except being out of memory which would cause a
	// run-time panic.
	var buf bytes.Buffer
	_ = writeBlockHeader(&buf, h)

	return DoubleSha256SH(buf.Bytes())
}

// writeBlockHeader writes a bitcoin block header to w.  See Serialize for
// encoding block headers to be stored to disk, such as in a database, as
// opposed to encoding for the wire.
func writeBlockHeader(w io.Writer, bh *BlockHeader) error {
	sec := uint32(bh.Timestamp.Unix())
	err := WriteElements(w, bh.PrevHash, bh.MerkleRoot, sec, bh.RootSig, bh.AggSig, bh.Tag)
	if err != nil {
		return err
	}

	return nil
}
func readBlockHeader(r io.Reader, bh *BlockHeader) error {
	var sec uint32
	err := ReadElements(r, &bh.PrevHash, &bh.MerkleRoot, &sec, &bh.RootSig, &bh.AggSig, &bh.Tag)
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
	return writeBlockHeader(w, h)
}
func (h *BlockHeader) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of readBlockHeader.
	return readBlockHeader(r, h)
}
func NewBlockHeader(prevHash *ShaHash, merkleRoot *ShaHash, rootSig NodeSig, aggSig AggSig, tag uint32) *BlockHeader {
	return &BlockHeader{

		PrevHash:   *prevHash,
		Timestamp:  time.Unix(time.Now().Unix(), 0),
		MerkleRoot: *merkleRoot,
		RootSig:    rootSig,
		AggSig:     aggSig,
		Tag:        tag,
	}
}

func NewBlock(head *BlockHeader) *Block {
	return &Block{
		Header: head,
	}
}
func (block *Block) AddTxs(msgs []DataMsg) {
	for _, m := range msgs {
		block.AddTransaction(Tx{m.Msg, m.Id})
	}
}
func TxsSerialize(w io.Writer, txs []Tx) error {
	var txsmsg [][datamsglehgth + idlength]byte
	var buf bytes.Buffer
	for _, tx := range txs {
		err := tx.Serialize(&buf)
		if err != nil {
			return err
		}
		var txmsg [datamsglehgth + idlength]byte
		copy(txmsg[:], buf.Bytes())
		txsmsg = append(txsmsg, txmsg)
		buf.Reset()
	}
	err := writeTxs(w, txsmsg...)
	if err != nil {
		return err
	}
	return nil
}
func TxsDeserialize(r *bytes.Reader) ([]Tx, error) {
	var txs []Tx
	txsmsg, err := readTxs(r)
	if err != nil {
		return nil, err
	}
	for _, txmsg := range txsmsg {
		var tx Tx
		buf := bytes.NewReader(txmsg[:])
		err = tx.Deserialize(buf)
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}
	return txs, nil
}
func (block *Block) BlockVerify(pubkey *btcec.PublicKey, top BlockHeader, pkg *aggSig_pkg.PKG) (bool, error) {
	//验证root签名
	merkletree := BuildMerkleTreeStore(block.Transactions)
	root := merkletree.Root()
	if root != block.Header.MerkleRoot {
		return false, errors.New("not the same merkle root")
	}
	rootsighash := [NodeSiglength]byte(block.Header.RootSig)
	rootSig, err := btcec.ParseDERSignature(rootsighash[:], btcec.S256())
	if err != nil {
		return false, err
	}
	if !rootSig.Verify(root[:], pubkey) {
		return false, errors.New("rootSig verify failed")
	}
	//验证prevhash
	var firsthash ShaHash
	copy(firsthash[:], []byte("1"))
	if block.Header.PrevHash != top.BlockSha() && block.Header.PrevHash != firsthash {
		return false, errors.New("prevhash verify failed")
	}
	//验证aggSig
	var aggSig aggSig_pkg.Signature
	var buf bytes.Buffer
	buf.Write(block.Header.AggSig[:])
	err = aggSig.Deserialize(&buf, pkg.Pairing)
	if err != nil {
		return false, err
	}
	var ids [][]byte
	var msgs [][]byte
	var msghash ShaHash
	for _, tx := range block.Transactions {
		ids = append(ids, tx.Id[:])
		msghash = fastsha256.Sum256(tx.Msg[:])
		msgs = append(msgs, msghash[:])
	}
	v, err := aggSig_pkg.Verify(&aggSig, ids, msgs, pkg)
	if err != nil {
		return false, err
	}
	if !v {
		return true, nil
	}
	return true, nil
}
func (block *Block) Serialize(w io.Writer) error {
	err := block.Header.Serialize(w)
	if err != nil {
		return err
	}
	err = TxsSerialize(w, block.Transactions)
	return err
}
func (block *Block) DeSerialize(reader *bytes.Reader) error {
	var newheader BlockHeader
	err:= newheader.Deserialize(reader)
	if err != nil {
		return err
	}
	newTXs, err := TxsDeserialize(reader)
	if err != nil {
		return err
	}
	block.Header = &newheader
	block.Transactions = newTXs
	return nil
}

func GenTestDataMsg(amount int,pkg *aggSig_pkg.PKG)([]DataMsg,error){
	var msgs []DataMsg
	var buf bytes.Buffer
	for i := 0; i < amount; i++ {
		buf.Reset()
		var data [datamsglehgth]byte
		var sensorId [4]byte
		copy(sensorId[:], []byte(string(i)))
		copy(data[:], time.Now().String())
		sensor := aggSig_pkg.Signer{
			ID:      sensorId[:],
			PkPair:  pkg.Gen(sensorId[:]),
			Pairing: pkg.Pairing,
		}
		sensorsig := sensor.Sign(data[:], pkg)
		err := sensorsig.Serialize(&buf)
		if err != nil {
			return nil,err
		}
		var sigmsg [35]byte
		copy(sigmsg[:], buf.Bytes())
		datamsg := DataMsg{
			Id:  sensorId,
			Msg: data,
			Sig: sigmsg,
		}
		msgs = append(msgs, datamsg)
	}
	return msgs,nil
}