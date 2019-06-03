package main

import (
	"bids_core/Blockchain"
	aggSig_pkg "bids_core/aggSig"
	"github.com/btcsuite/btcd/btcec"
)

type Node struct {
	NodeID     uint32
	NodeTable  map[uint32]string // key=nodeID, value=url
	PKTable    map[uint32]*btcec.PublicKey
	privateKey *btcec.PrivateKey
	pkg        *aggSig_pkg.PKG
	tops       map[uint32]Blockchain.BlockHeader
	Prepared   map[uint32]Proposal
	PreparedNum map[uint32]int
	preparelog map[uint32][]*Prepared
	Done chan struct{}
}
