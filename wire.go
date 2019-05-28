package bids_core

import (
	"bytes"
	"errors"
	"github.com/btcsuite/btcd/btcec"
	"io"
	"bids_core/Blockchain"
)

type Proposal struct {
	Abst  ProposalAbst
	Block *Blockchain.Block
}

type ProposalAbst struct {
	Proposer string
	Hash     Blockchain.ShaHash
}

type Prepared struct {
	Abst   ProposalAbst
	Id     string
	Result bool
	Sig    *btcec.Signature
}

func (node *Node) NewProposal(block *Blockchain.Block) *Proposal {
	return &Proposal{
		Abst: ProposalAbst{
			Proposer: node.NodeID,
			Hash:     block.Header.BlockSha(),
		},
		Block: block,
	}
}

func (proposal *Proposal) Serialize(w io.Writer) error {
	err := proposal.Block.Header.Serialize(w)
	if err != nil {
		return err
	}
	err = Blockchain.TxsSerialize(w, proposal.Block.Transactions)
	if err != nil {
		return err
	}
	err = Blockchain.WriteElement(w, proposal.Abst.Hash)
	if err != nil {
		return err
	}
	var id [16]byte
	copy(id[:], []byte(proposal.Abst.Proposer))
	err = Blockchain.WriteElement(w, id)
	if err != nil {
		return err
	}
	return nil
}

func (proposal *Proposal) Deserialize(r *bytes.Reader) error {
	err := proposal.Block.Header.Deserialize(r)
	if err != nil {
		return err
	}
	proposal.Block.Transactions, err = Blockchain.TxsDeserialize(r)
	if err != nil {
		return err
	}
	err = Blockchain.ReadElement(r, &proposal.Abst.Hash)
	if err != nil {
		return err
	}
	var idmsg [16]byte
	err = Blockchain.ReadElement(r, &idmsg)
	if err != nil {
		return err
	}
	proposal.Abst.Proposer = string(idmsg[:])
	return nil
}

func (node *Node) ProposalVerify(proposal *Proposal) (bool, error) {
	block := proposal.Block
	return block.BlockVerify(node.PKTable[proposal.Abst.Proposer], node.tops[block.Header.Tag], &node.pkg)
}

func (node *Node) NewPrepared(proposal Proposal) (*Prepared, error) {
	temp := []byte(proposal.Abst.Proposer)
	var proposerid [16]byte
	copy(proposerid[:], temp)
	var buf bytes.Buffer
	err := Blockchain.WriteElement(&buf, proposerid)
	if err != nil {
		return nil, err
	}
	err = Blockchain.WriteElement(&buf, proposal.Abst.Hash)
	if err != nil {
		return nil, err
	}
	temp = []byte(node.NodeID)
	var preparerId [16]byte
	copy(preparerId[:], temp)
	err = Blockchain.WriteElement(&buf, preparerId)
	if err != nil {
		return nil, err
	}
	result := bool(true)
	err = Blockchain.WriteElement(&buf, result)
	if err != nil {
		return nil, err
	}
	sig, err := node.privateKey.Sign(buf.Bytes())
	if err != nil {
		return nil, err
	}
	prepared := &Prepared{
		Abst:   proposal.Abst,
		Id:     node.NodeID,
		Result: result,
		Sig:    sig,
	}
	return prepared, nil
}

func (prepare *Prepared) Serialize(w io.Writer) error {
	temp := []byte(prepare.Abst.Proposer)
	var proposerid [16]byte
	copy(proposerid[:], temp)
	err := Blockchain.WriteElement(w, proposerid)
	if err != nil {
		return err
	}
	err = Blockchain.WriteElement(w, prepare.Abst.Hash)
	if err != nil {
		return err
	}
	temp = []byte(prepare.Id)
	var preparerId [16]byte
	copy(preparerId[:], temp)
	err = Blockchain.WriteElement(w, preparerId)
	if err != nil {
		return err
	}
	result := bool(true)
	err = Blockchain.WriteElement(w, result)
	if err != nil {
		return err
	}
	sigmsg := prepare.Sig.Serialize()
	var s [Blockchain.NodeSiglength]byte
	copy(s[:], sigmsg)
	err = Blockchain.WriteElement(w, s)
	if err != nil {
		return err
	}
	return nil
}

func (prepare *Prepared) Deserialize(r io.Reader) error {
	var proposerId, prepareId [16]byte
	var s [Blockchain.NodeSiglength]byte
	err := Blockchain.ReadElement(r, &proposerId)
	if err != nil {
		return err
	}
	var temp, temp2 []byte
	temp = append(temp, proposerId[:]...)
	prepare.Abst.Proposer = string(temp)
	err = Blockchain.ReadElements(r, &prepare.Abst.Hash, &prepareId, &prepare.Result, &s)
	if err != nil {
		return err
	}
	temp2 = append(temp2, prepareId[:]...)
	prepare.Id = string(temp2)
	sig, err := btcec.ParseDERSignature(s[:], btcec.S256())
	if err != nil {
		return err
	}
	prepare.Sig = sig
	return nil
}

func (abst *ProposalAbst) Equal(comp ProposalAbst) bool {
	return abst.Hash.IsEqual(&comp.Hash) && abst.Proposer == comp.Proposer
}

func (node *Node) VerifyPrepared(prepare Prepared) (bool, error) {
	if !prepare.Result {
		return false, nil
	}
	var w bytes.Buffer
	temp := []byte(prepare.Abst.Proposer)
	var proposerid [16]byte
	copy(proposerid[:], temp)
	err := Blockchain.WriteElement(&w, proposerid)
	if err != nil {
		return false, err
	}
	err = Blockchain.WriteElement(&w, prepare.Abst.Hash)
	if err != nil {
		return false, err
	}
	temp = []byte(prepare.Id)
	var preparerId [16]byte
	copy(preparerId[:], temp)
	err = Blockchain.WriteElement(&w, preparerId)
	if err != nil {
		return false, err
	}
	result := bool(true)
	err = Blockchain.WriteElement(&w, result)
	if err != nil {
		return false, err
	}
	if ! prepare.Sig.Verify(w.Bytes(), node.PKTable[prepare.Id]) {
		return false, nil
	}
	if !prepare.Abst.Equal(node.Prepared[prepare.Abst.Proposer]) {
		return false, errors.New("not the same prepared")
	}
	return true,nil

}
