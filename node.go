package main

import (
	"github.com/btcsuite/btcd/btcec"
	"main/Blockchain"
	aggSig_pkg "main/aggSig"
)

type Node struct {
	NodeID        string
	NodeTable     map[string]string // key=nodeID, value=url
	PKTable 	  map[string]btcec.PublicKey
	privateKey    btcec.PrivateKey
	pkg 		  aggSig_pkg.PKG
	tops		  map[uint32]Blockchain.BlockHeader
}

func NewNode(nodeID string)*Node  {
	return &Node{
		NodeID:nodeID,
		NodeTable:map[string]string{
			"Apple": "localhost:1111",
			"MS": "localhost:1112",
			"Google": "localhost:1113",
			"IBM": "localhost:1114",
		},
	}
}
