package Blockchain

import (
	"btcd/btcec"
	"bytes"
	"fmt"
	"testing"
)

func TestSerialize(t *testing.T)  {
	prevSha := new(ShaHash)
	merkleRoot := new(ShaHash)
	var rootSig [NodeSiglength]byte
	copy(rootSig[:],[]byte("123"))
	var aggSig [AggSiglength]byte
	copy(aggSig[:],[]byte("123"))
	header := NewBlockHeader(prevSha,merkleRoot,rootSig,aggSig,uint32(1))
	fmt.Printf("%v \n",header)
	fmt.Printf("%v \n ",header.BlockSha())
	var buf bytes.Buffer
	err := header.Serialize(&buf)
	if err!=nil {
		t.Fatal(err)
	}
	fmt.Printf("%v \n",buf.Bytes())
	var re BlockHeader
	rbuf := bytes.NewReader(buf.Bytes())
	err  = re.Deserialize(rbuf)
	if err!=nil {
		t.Fatal(err)
	}
	fmt.Printf("%v \n",re)
	var msg [datamsglehgth]byte
	var id [idlength]byte
	copy(msg[:],[]byte("hello"))
	copy(id[:],[]byte("12"))
	tx1:=Tx{msg,id}
	var buf1 bytes.Buffer
	tx1.Serialize(&buf1)
	fmt.Printf("%v\n",buf1.Bytes())
	buf2 := bytes.NewReader(buf1.Bytes())
	var tx Tx
	tx.Deserialize(buf2)
	fmt.Printf("%v\n",tx)
}

func TestSig(t *testing.T){
	 priv,err := btcec.NewPrivateKey(btcec.S256())
	 if err!=nil{
	 	t.Fatal(err)
	 }
	 msg := []byte("hello")
	 sig,err:=priv.Sign(msg)
	if err!=nil{
		t.Fatal(err)
	}
	seri :=  sig.Serialize()
	sigde,err := btcec.ParseDERSignature(seri,btcec.S256())
	if err!=nil{
		t.Fatal(err)
	}
	t.Log(len(seri))
	t.Logf("%v\n",bytes.Equal(seri,sigde.Serialize()))
	t.Log(sig.Verify(msg,priv.PubKey()))
	t.Log(sigde.Verify(msg,priv.PubKey()))
}
func TestTx_Serialize(t *testing.T) {
	var msg [datamsglehgth]byte
	var id [idlength]byte
	copy(msg[:],[]byte("hello"))
	copy(id[:],[]byte("12"))
	tx1:=Tx{msg,id}
	tx2:=tx1
	Txs:=[]Tx{tx1,tx2}
	var buf bytes.Buffer
	err:=TxsSerialize(&buf,Txs)
	if err!=nil {
		t.Fatal(err)
	}
	fmt.Printf("%v\n",buf.Bytes())
	reader:=bytes.NewReader(buf.Bytes())
	fmt.Println(reader.Len())
	newtxs,err := TxsDeserialize(reader)
	if err!=nil {
		t.Fatal(err)
	}
	fmt.Printf("%v\n", newtxs)
}
