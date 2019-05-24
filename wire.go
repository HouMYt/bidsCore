package main

import (
	"btcd/btcec"
	"encoding/json"
	"io"
	"main/Blockchain"
)
type Proposal struct {
	Abst ProposalAbst
	Block *Blockchain.Block
}
type ProposalAbst struct {
	Index uint32
	Proposer string
	hash Blockchain.ShaHash
}
type Prepared struct {
	Abst ProposalAbst
	Id string
	result bool
	sig *btcec.Signature
}
func (node *Node)NewProposal(block *Blockchain.Block)*Proposal{
	return &Proposal{
	Abst:ProposalAbst{Index:node.GetIndex(),
		Proposer:node.NodeID,
		hash:block.Header.BlockSha(),
	},
		Block:block,
	}
}
func (proposal *Proposal)Serialize()([]byte,error){
	return json.Marshal(proposal)
}
func (proposal *Proposal)Deserialize(r io.Reader)error{
	return json.NewDecoder(r).Decode(proposal)
}
func (node *Node)GetIndex()uint32{
	return node.TopIndex
}
func (node *Node)VerifyPrepared(prepared Prepared)bool{
	pk := node.PKTable[prepared.Id]
	hash,err := json.Marshal(Prepared{Abst:prepared.Abst,Id:prepared.Id,result:prepared.result})
	if err!=nil{
		return false
	}
	return prepared.sig.Verify(hash,&pk)
}
func (node *Node)SignPrepared(prepared *Prepared)error{
	hash,err := json.Marshal(Prepared{Abst:prepared.Abst,Id:prepared.Id,result:prepared.result})
	if err!=nil{
		return err
	}
	sig,err := node.privateKey.Sign(hash)
	if err!=nil{
		return err
	}
	prepared.sig = sig
	return nil
}
func ()  {
	
}