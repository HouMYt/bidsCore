package bids_core

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSerialize(t *testing.T)  {
	prevSha := new(ShaHash)
	merkleRoot := new(ShaHash)
	var rootSig [RootSiglength]byte
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

}
