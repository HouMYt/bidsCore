package main

import (
	"bytes"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec"
	"io"
	"main/Blockchain"
)

type Proposal struct {
	Abst  ProposalAbst
	Block *Blockchain.Block
}
type ProposalAbst struct {
	Proposer string
	hash     Blockchain.ShaHash
}
type Prepared struct {
	Abst   ProposalAbst
	Id     string
	result bool
	sig    *btcec.Signature
}

func (node *Node) NewProposal(block *Blockchain.Block) *Proposal {
	return &Proposal{
		Abst: ProposalAbst{
			Proposer: node.NodeID,
			hash:     block.Header.BlockSha(),
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
	err = Blockchain.WriteElement(w, proposal.Abst.hash)
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
	proposal.Block.Transactions,err = Blockchain.TxsDeserialize(r)
	if err != nil {
		return err
	}
	err = Blockchain.ReadElement(r,&proposal.Abst.hash)
	if err != nil {
		return err
	}
	var idmsg [16]byte
	err = Blockchain.ReadElement(r,&idmsg)
	if err != nil {
		return err
	}
	proposal.Abst.Proposer = string(idmsg[:])
	return nil
}

func (node *Node) VerifyPrepared(prepared Prepared) bool {
	pk := node.PKTable[prepared.Id]
	hash, err := json.Marshal(Prepared{Abst: prepared.Abst, Id: prepared.Id, result: prepared.result})
	if err != nil {
		return false
	}
	return prepared.sig.Verify(hash, &pk)
}
func (node *Node) SignPrepared(prepared *Prepared) error {
	hash, err := json.Marshal(Prepared{Abst: prepared.Abst, Id: prepared.Id, result: prepared.result})
	if err != nil {
		return err
	}
	sig, err := node.privateKey.Sign(hash)
	if err != nil {
		return err
	}
	prepared.sig = sig
	return nil
}
func (node *Node) ProposalVerify(proposal *Proposal) (bool, error) {
	block := proposal.Block
	pk := node.PKTable[proposal.Abst.Proposer]
	return block.BlockVerify(&pk, node.tops[block.Header.Tag], &node.pkg)
}
