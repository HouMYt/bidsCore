package main

import (
	"bids_core/Blockchain"
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/btcsuite/btcd/btcec"
	"io"
)

type Proposal struct {
	Abst  ProposalAbst
	Block Blockchain.Block
}

type ProposalAbst struct {
	Proposer uint32
	Hash     Blockchain.ShaHash
}

type Prepared struct {
	Abst   ProposalAbst
	Id     uint32
	Result bool
	Sig    *btcec.Signature
}

func (node *Node) NewProposal(block *Blockchain.Block) *Proposal {
	return &Proposal{
		Abst: ProposalAbst{
			Proposer: node.NodeID,
			Hash:     block.Header.BlockSha(),
		},
		Block: *block,
	}
}

func (proposal *Proposal) Serialize(w io.Writer) error {
	err:=proposal.Block.Serialize(w)
	if err != nil {
		return err
	}
	err = Blockchain.WriteElement(w, proposal.Abst.Hash)
	if err != nil {
		return err
	}
	err = Blockchain.WriteElement(w, proposal.Abst.Proposer)
	if err != nil {
		return err
	}
	return nil
}

func (proposal *Proposal) Deserialize(r *bytes.Reader) error {
	err := proposal.Block.DeSerialize(r)
	if err != nil {
		return err
	}
	err = Blockchain.ReadElement(r, &proposal.Abst.Hash)
	if err != nil {
		return err
	}
	err = Blockchain.ReadElement(r, &proposal.Abst.Proposer)
	if err != nil {
		return err
	}
	return nil
}

func (node *Node) ProposalVerify(proposal *Proposal) (bool, error) {
	block := proposal.Block
	return block.BlockVerify(node.PKTable[proposal.Abst.Proposer], node.tops[block.Header.Tag], node.pkg)
}

func (node *Node) NewPrepared(proposal *Proposal) (*Prepared, error) {
	var buf bytes.Buffer
	err := Blockchain.WriteElement(&buf, proposal.Abst.Proposer)
	if err != nil {
		return nil, err
	}
	err = Blockchain.WriteElement(&buf, proposal.Abst.Hash)
	if err != nil {
		return nil, err
	}
	err = Blockchain.WriteElement(&buf, node.NodeID)
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
	prepared := Prepared{
		Abst:   proposal.Abst,
		Id:     node.NodeID,
		Result: result,
		Sig:    sig,
	}
	return &prepared, nil
}

func (prepare *Prepared) Serialize(w io.Writer) error {
	err := Blockchain.WriteElement(w, prepare.Abst.Proposer)
	if err != nil {
		return err
	}
	err = Blockchain.WriteElement(w, prepare.Abst.Hash)
	if err != nil {
		return err
	}
	err = Blockchain.WriteElement(w, prepare.Id)
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
	var s [Blockchain.NodeSiglength]byte
	err := Blockchain.ReadElements(r, &prepare.Abst.Proposer,&prepare.Abst.Hash, &prepare.Id, &prepare.Result, &s)
	if err != nil {
		return err
	}
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

func (node *Node) VerifyPrepared(prepare *Prepared) (bool, error) {
	if !prepare.Result {
		return false, nil
	}
	var w bytes.Buffer
	err := Blockchain.WriteElement(&w, prepare.Abst.Proposer)
	if err != nil {
		return false, err
	}
	err = Blockchain.WriteElement(&w, prepare.Abst.Hash)
	if err != nil {
		return false, err
	}
	err = Blockchain.WriteElement(&w, prepare.Id)
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
	if !prepare.Abst.Equal(node.Prepared[prepare.Abst.Proposer].Abst) {
		return false, errors.New("not the same prepared")
	}
	return true,nil

}
func MsgEncode(reader io.Reader,msg []byte)error{
	var buf []byte
	hex.Encode(buf,msg)
	_,err := reader.Read(buf)
	return err
}
func MsgDecode( msgencode []byte)( msg []byte,err error) {
	_,err = hex.Decode(msg,msgencode)
	return msg,err
}