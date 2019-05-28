package bids_core

import (
	"bids_core/Blockchain"
	aggSig_pkg "bids_core/aggSig"
	"github.com/btcsuite/btcd/btcec"
)

type Node struct {
	NodeID     string
	NodeTable  map[string]string // key=nodeID, value=url
	PKTable    map[string]*btcec.PublicKey
	privateKey btcec.PrivateKey
	pkg        aggSig_pkg.PKG
	tops       map[uint32]Blockchain.BlockHeader
	Prepared   map[string]ProposalAbst
}

func NewNode(nodeID string) *Node {
	return &Node{
		NodeID: nodeID,
		NodeTable: map[string]string{
			"Apple":  "localhost:1111",
			"MS":     "localhost:1112",
			"Google": "localhost:1113",
			"IBM":    "localhost:1114",
		},
	}
}
