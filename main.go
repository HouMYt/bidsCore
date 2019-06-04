package main

import (
	"bids_core/Blockchain"
	aggSig_pkg "bids_core/aggSig"
	"bytes"
	"flag"
	"fmt"
	"github.com/Nik-U/pbc"
	"github.com/btcsuite/btcd/btcec"
	"strconv"
	"time"
)

var sensorlen = flag.Int("s", 10, "sensor length")
var nodelen = flag.Int("n", 4, "node length")

func main() {
	flag.Parse()
	pairing, err := pbc.NewPairingFromString("type a\nq 4025338979\nh 6279780\nr 641\nexp2 9\nexp1 7\nsign1 1\nsign0 1\n")
	if err != nil {
		panic(err)
	}
	generator := pairing.NewG2()
	generator.Rand()
	secretKey := pairing.NewZr().Rand()
	pubicKey := pairing.NewG2()
	pubicKey.PowZn(generator, secretKey)
	pkg := &aggSig_pkg.PKG{
		Pairing:   pairing,
		Generator: generator,
		SecretKey: secretKey,
		PublicKey: pubicKey,
	}
	pubKeyTable := make(map[uint32]*btcec.PublicKey)
	UrlTable := make(map[uint32]string)
	var nodes []Node
	var servers []Server
	for i := 1; i < *nodelen+1; i++ {
		privKey, _ := btcec.NewPrivateKey(btcec.S256())
		pubKeyTable[uint32(i)] = privKey.PubKey()
		UrlTable[uint32(i)] = "localhost:" + strconv.Itoa(6600+i)
		node := Node{
			NodeID:     uint32(i),
			privateKey: privKey,
			pkg:        pkg,
		}
		nodes = append(nodes, node)
	}
	fmt.Printf("%v\n",UrlTable)
	for index := range nodes {
		nodes[index].PKTable = pubKeyTable
		nodes[index].NodeTable = UrlTable
		nodes[index].Prepared = make(map[uint32]Proposal)
		nodes[index].tops = make(map[uint32]Blockchain.BlockHeader)
		nodes[index].PreparedNum = make(map[uint32]int)
		nodes[index].preparelog = make(map[uint32][]*Prepared)
		server := NewServer(&nodes[index])
		servers = append(servers, *server)
		nodes[index].Done = make(chan struct{})
	}
	for i := range servers {
		go servers[i].Start()
		go servers[i].Send()
	}
	//test block
	//Gen data msg
	var txs []Blockchain.Tx
	var sensorsigs []*aggSig_pkg.Signature
	var buf bytes.Buffer
	var msgs []Blockchain.DataMsg
	for i := 0; i < *sensorlen; i++ {
		buf.Reset()
		var data [64]byte
		var sensorId [4]byte
		copy(sensorId[:], []byte(string(i)))
		copy(data[:], time.Now().String())
		tx := Blockchain.Tx{data, sensorId}
		txs = append(txs, tx)
		sensor := aggSig_pkg.Signer{
			ID:      sensorId[:],
			PkPair:  pkg.Gen(sensorId[:]),
			Pairing: pairing,
		}
		sensorsig := sensor.Sign(data[:], pkg)
		sensorsigs = append(sensorsigs, sensorsig)
		sensorsig.Serialize(&buf)
		var sigmsg [35]byte
		copy(sigmsg[:], buf.Bytes())
		datamsg := Blockchain.DataMsg{
			Id:  sensorId,
			Msg: data,
			Sig: sigmsg,
		}
		msgs = append(msgs, datamsg)
	}

	//start ticking--------------------------------
	start := time.Now()
	buf.Reset()
	merkleroot := Blockchain.BuildMerkleTreeStore(txs)
	root := merkleroot.Root()
	rootsig, _ := servers[0].node.privateKey.Sign(root[:])
	var rootsighash Blockchain.NodeSig
	copy(rootsighash[:], rootsig.Serialize())
	aggsig, _ := aggSig_pkg.AggSig(sensorsigs)
	aggsig.Serialize(&buf)
	var aggSighash Blockchain.AggSig
	copy(aggSighash[:], buf.Bytes())
	buf.Reset()
	var firsthash Blockchain.ShaHash
	copy(firsthash[:], []byte("1"))
	header := Blockchain.NewBlockHeader(&firsthash, &root, rootsighash, aggSighash, uint32(1))
	block := Blockchain.NewBlock(header)
	block.AddTxs(msgs)
	proposal := servers[0].node.NewProposal(block)
	servers[0].node.Prepared[proposal.Abst.Proposer] = *proposal
	err = proposal.Serialize(&buf)
	fmt.Println(buf.Len())
	firstmsg := Outmsg{"Proposal", buf.Bytes()}
	servers[0].msgqueue <- firstmsg
	for i := range servers {
		<-servers[i].node.Done
	}
	fmt.Println(time.Now().Sub(start))

}
