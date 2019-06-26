package main

import (
	"bids_core/Blockchain"
	aggSig_pkg "bids_core/aggSig"
	"bytes"
	"fmt"
	"github.com/Nik-U/pbc"
	"github.com/btcsuite/btcd/btcec"
	"testing"
	"time"
)

func testPairing(t *testing.T) *pbc.Pairing {
	// Generated with pbc_param_init_a_gen(p, 10, 32);
	pairing, err := pbc.NewPairingFromString("type a\nq 4025338979\nh 6279780\nr 641\nexp2 9\nexp1 7\nsign1 1\nsign0 1\n")
	if err != nil {
		t.Fatalf("Could not instantiate test pairing")
	}

	return pairing
}
func TestWire(t *testing.T) {

	//test pkg pairing
	pairing, err := pbc.NewPairingFromString("type a\nq 4025338979\nh 6279780\nr 641\nexp2 9\nexp1 7\nsign1 1\nsign0 1\n")
	if err != nil {
		t.Fatalf("Could not instantiate test pairing")
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

	//test nodes
	privKey1, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	publicKey1 := privKey1.PubKey()
	node1 := Node{
		NodeID:     uint32(1),
		pkg:        pkg,
		privateKey: privKey1,
	}
	node1.PKTable = make(map[uint32]*btcec.PublicKey)
	node1.PKTable[uint32(1)] = publicKey1

	//test block
	var data1, data2 [1024]byte
	var sensorId1, sensorId2 [4]byte
	copy(data1[:], []byte("hello"))
	copy(data2[:], []byte("world"))
	copy(sensorId1[:], []byte("1"))
	copy(sensorId2[:], []byte("2"))
	tx1 := Blockchain.Tx{data1, sensorId1}
	tx2 := Blockchain.Tx{data2, sensorId2}
	txs := []Blockchain.Tx{tx1, tx2}
	merkleroot := Blockchain.BuildMerkleTreeStore(txs)
	root := merkleroot.Root()
	rootsig, err := node1.privateKey.Sign(root[:])
	if err != nil {
		t.Fatal(err)
	}
	var rootsighash Blockchain.NodeSig
	copy(rootsighash[:], rootsig.Serialize())
	sensor1 := aggSig_pkg.Signer{
		ID:      sensorId1[:],
		PkPair:  pkg.Gen(sensorId1[:]),
		Pairing: pairing,
	}
	sensor2 := aggSig_pkg.Signer{
		ID:      sensorId2[:],
		PkPair:  pkg.Gen(sensorId2[:]),
		Pairing: pairing,
	}
	sensorsig1 := sensor1.Sign([]byte("hello"), pkg)
	sensorsig2 := sensor2.Sign([]byte("world"), pkg)
	sensorsigs := []*aggSig_pkg.Signature{sensorsig1, sensorsig2}
	aggsig, err := aggSig_pkg.AggSig(sensorsigs)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = aggsig.Serialize(&buf)
	if err != nil {
		t.Fatal(err)
	}
	var aggSighash Blockchain.AggSig
	copy(aggSighash[:], buf.Bytes())
	var firsthash Blockchain.ShaHash
	copy(firsthash[:], []byte("1"))
	header := Blockchain.NewBlockHeader(&firsthash, &root, rootsighash, aggSighash, uint32(1))
	block := Blockchain.NewBlock(header)
	block.AddTransaction(tx1)
	block.AddTransaction(tx2)

	//verify block
	ok, err := block.BlockVerify(node1.privateKey.PubKey(), *block.Header, pkg)
	fmt.Printf("BlockVerify: %v\n", ok)
	if err != nil {
		fmt.Printf("BlockVerify err: %v\n", err)
	}

	//serialize block
	buf.Reset()
	err = block.Serialize(&buf)
	fmt.Printf("block length: %v\n", buf.Len())
	var newheader Blockchain.BlockHeader
	err = newheader.Deserialize(&buf)
	if err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(buf.Bytes())
	newTXs, err := Blockchain.TxsDeserialize(reader)
	if err != nil {
		t.Fatal(err)
	}
	newblock := Blockchain.NewBlock(&newheader)
	newblock.Transactions = newTXs
	newok, err := newblock.BlockVerify(node1.privateKey.PubKey(), *newblock.Header, pkg)
	fmt.Printf("BlockVerify: %v\n", newok)
	if err != nil {
		fmt.Printf("BlockVerify err: %v\n", err)
	}

	//test proposal
	buf.Reset()

	proposal := node1.NewProposal(block)
	err = proposal.Serialize(&buf)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Proposal length: %v\n", buf.Len())
	prook, err := node1.ProposalVerify(proposal)
	if err != nil {
		fmt.Printf("%v\n", err)
	}
	fmt.Printf("proposal verify : %v\n", prook)
	var newpro Proposal
	reader.Reset(buf.Bytes())
	err = newpro.Deserialize(reader)
	if err != nil {
		fmt.Printf("%v\n", err)
	}
	newprook, err := node1.ProposalVerify(proposal)
	if err != nil {
		fmt.Printf("%v\n", err)
	}
	fmt.Printf("proposal verify : %v\n", newprook)

	//test prepare
	prepare, err := node1.NewPrepared(proposal)
	if err != nil {
		t.Fatal(err)
	}
	node1.Prepared = make(map[uint32]Proposal)
	node1.Prepared[prepare.Abst.Proposer] = *proposal
	prepareok, err := node1.VerifyPrepared(prepare)
	if err != nil {
		fmt.Printf("err: %v\n", err)
	}
	fmt.Printf("prepare verify: %v\n", prepareok)
	buf.Reset()
	err = prepare.Serialize(&buf)
	if err != nil {
		t.Fatal(err)
	}
	var newprepare Prepared
	err = newprepare.Deserialize(&buf)
	if err != nil {
		t.Fatal(err)
	}
	newprepareok, err := node1.VerifyPrepared(&newprepare)
	if err != nil {
		fmt.Printf("err: %v\n", err)
	}
	fmt.Printf("newprepare verify: %v\n", newprepareok)

}

func BenchmarkBlockGen(b *testing.B) {
	//test pkg pairing
	pairing, err := pbc.NewPairingFromString("type a\nq 4025338979\nh 6279780\nr 641\nexp2 9\nexp1 7\nsign1 1\nsign0 1\n")
	if err != nil {
		b.Fatalf("Could not instantiate test pairing")
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

	//test nodes
	privKey1, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		b.Fatal(err)
	}
	publicKey1 := privKey1.PubKey()
	node1 := Node{
		NodeID:     uint32(1),
		pkg:        pkg,
		privateKey: privKey1,
	}
	node1.PKTable = make(map[uint32]*btcec.PublicKey)
	node1.PKTable[uint32(1)] = publicKey1
	datalength := 5
	var txs []Blockchain.Tx
	var sensorsigs []*aggSig_pkg.Signature
	var msgs []Blockchain.DataMsg
	var buf bytes.Buffer


	//Gen data msg
	for i := 0; i < datalength; i++ {
		var data  [1024]byte
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
		err := sensorsig.Serialize(&buf)
		if err!=nil {
			b.Fatal(err)
		}
		var   sigmsg [35]byte
		copy(sigmsg[:],buf.Bytes())
		datamsg := Blockchain.DataMsg{
			Id : sensorId,
			Msg:data,
			Sig:sigmsg,
		}
		msgs = append(msgs, datamsg)
	}

	size:=0
	buf.Reset()
	b.ResetTimer()
	b.N = 5000
	for i := 0; i < b.N; i++ {
		buf.Reset()
		//test block
		merkleroot := Blockchain.BuildMerkleTreeStore(txs)
		root := merkleroot.Root()
		rootsig, err := node1.privateKey.Sign(root[:])
		if err != nil {
			b.Fatal(err)
		}
		var rootsighash Blockchain.NodeSig
		copy(rootsighash[:], rootsig.Serialize())
		aggsig, err := aggSig_pkg.AggSig(sensorsigs)
		if err != nil {
			b.Fatal(err)
		}
		var buf bytes.Buffer
		err = aggsig.Serialize(&buf)
		if err != nil {
			b.Fatal(err)
		}
		var aggSighash Blockchain.AggSig
		copy(aggSighash[:], buf.Bytes())
		var firsthash Blockchain.ShaHash
		copy(firsthash[:], []byte("1"))
		header := Blockchain.NewBlockHeader(&firsthash, &root, rootsighash, aggSighash, uint32(1))
		block := Blockchain.NewBlock(header)
		block.AddTxs(msgs)
		err = block.Serialize(&buf)
		if err!=nil {
			b.Fatal(err)
		}
		size = size + buf.Len()
	}
	b.Log(size)
}
func BenchmarkSensorSign(b *testing.B) {
	//test pkg pairing
	pairing, err := pbc.NewPairingFromString("type a\nq 4025338979\nh 6279780\nr 641\nexp2 9\nexp1 7\nsign1 1\nsign0 1\n")
	if err != nil {
		b.Fatalf("Could not instantiate test pairing")
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

	//test nodes
	privKey1, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		b.Fatal(err)
	}
	publicKey1 := privKey1.PubKey()
	node1 := Node{
		NodeID:     uint32(1),
		pkg:        pkg,
		privateKey: privKey1,
	}
	node1.PKTable = make(map[uint32]*btcec.PublicKey)
	node1.PKTable[uint32(1)] = publicKey1
	b.ResetTimer()
	b.N = 5000
	for i := 0; i < b.N; i++ {
		//Gen data msg
		var data1, data2 [64]byte
		var sensorId1, sensorId2 [4]byte
		copy(data1[:], time.Now().String())
		copy(data2[:], time.Now().String())
		copy(sensorId1[:], []byte("1"))
		copy(sensorId2[:], []byte("2"))
		sensor1 := aggSig_pkg.Signer{
			ID:      sensorId1[:],
			PkPair:  pkg.Gen(sensorId1[:]),
			Pairing: pairing,
		}
		sensor2 := aggSig_pkg.Signer{
			ID:      sensorId2[:],
			PkPair:  pkg.Gen(sensorId2[:]),
			Pairing: pairing,
		}
		sensor1.Sign([]byte("hello"), pkg)
		sensor2.Sign([]byte("world"), pkg)
	}
}
func TestBuf(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte("123"))
	fmt.Printf("%v", []byte("123"))
	fmt.Printf("%v", buf.Bytes())
}
func TestDiv(t *testing.T)  {
	a := 10
	fmt.Println(a/3)
}