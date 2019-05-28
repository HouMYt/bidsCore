package bids_core

import (
	"bids_core/Blockchain"
	"github.com/Nik-U/pbc"
	"testing"
)

func newTestBlock(t *testing.T)Blockchain.Block{

}
func newTestNodes(t *testing.T)[]Node{

}
func testPairing(t *testing.T) *pbc.Pairing {
	// Generated with pbc_param_init_a_gen(p, 10, 32);
	pairing, err := pbc.NewPairingFromString("type a\nq 4025338979\nh 6279780\nr 641\nexp2 9\nexp1 7\nsign1 1\nsign0 1\n")
	if err != nil {
		t.Fatalf("Could not instantiate test pairing")
	}

	return pairing
}
func TestWire(t *testing.T)  {

}