package main

import "btcd/btcec"

type Node struct {
	NodeID        string
	NodeTable     map[string]string // key=nodeID, value=url
	PKTable 	  map[string]btcec.PublicKey
	TopIndex	  uint32
	privateKey    btcec.PrivateKey
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
