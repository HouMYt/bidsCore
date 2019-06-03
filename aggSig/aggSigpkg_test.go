package aggSig_pkg

import (
	"bytes"
	"fmt"
	"github.com/Nik-U/pbc"
	"testing"
)

func testPairing(t *testing.T) *pbc.Pairing {
	// Generated with pbc_param_init_a_gen(p, 10, 32);
	pairing, err := pbc.NewPairingFromString("type a\nq 4025338979\nh 6279780\nr 641\nexp2 9\nexp1 7\nsign1 1\nsign0 1\n")
	if err != nil {
		t.Fatalf("Could not instantiate test pairing")
	}

	return pairing
}

func TestAggSig_pkg(t *testing.T) {
	pairing := testPairing(t)
	generator := pairing.NewG2()
	generator.Rand()
	secretKey := pairing.NewZr().Rand()
	pubicKey := pairing.NewG2()
	pubicKey.PowZn(generator, secretKey)
	pkg := &PKG{
		Pairing:   pairing,
		Generator: generator,
		SecretKey: secretKey,
		PublicKey: pubicKey,
	}
	signers := make([]Signer, 3)
	signers[0].ID = []byte("12345")
	signers[1].ID = []byte("23456")
	signers[2].ID = []byte("33457")
	for i := range signers {
		signers[i].Pairing = pairing
		signers[i].PkPair = pkg.Gen(signers[i].ID)
	}
	fmt.Printf("%v", pkg.PublicKey.Sign())
	msgs := [][]byte{[]byte("12llgas3"), []byte("24fasd351"), []byte("safasfd")}
	s0 := signers[0].Sign(msgs[0], pkg)
	s1 := signers[1].Sign(msgs[1], pkg)
	s2 := signers[2].Sign(msgs[2], pkg)
	sigs := []*Signature{s0, s1, s2}
	aggSig, err := AggSig(sigs)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("w length: %v \n", len(aggSig.w))
	fmt.Printf("s length: %v \n", len(aggSig.S.Bytes()))
	fmt.Printf("t length: %v \n", len(aggSig.T.Bytes()))

	ids := [][]byte{signers[0].ID, signers[1].ID, signers[2].ID}
	//msgsfake :=[][]byte{[]byte("12llgll3"),[]byte("24fasd351"),[]byte("safasfd")}
	result, err := Verify(aggSig, ids, msgs, pkg)
	t.Logf("%v", result)
	if err != nil {
		t.Log(err)
	}
}
func TestSignature_Serialize(t *testing.T) {
	pairing := testPairing(t)
	generator := pairing.NewG2()
	generator.Rand()
	secretKey := pairing.NewZr().Rand()
	pubicKey := pairing.NewG2()
	pubicKey.PowZn(generator, secretKey)
	pkg := &PKG{
		Pairing:   pairing,
		Generator: generator,
		SecretKey: secretKey,
		PublicKey: pubicKey,
	}
	signers := make([]Signer, 3)
	signers[0].ID = []byte("12345")
	signers[1].ID = []byte("23456")
	signers[2].ID = []byte("33457")
	for i := range signers {
		signers[i].Pairing = pairing
		signers[i].PkPair = pkg.Gen(signers[i].ID)
	}
	fmt.Printf("%v", pkg.PublicKey.Sign())
	msgs := [][]byte{[]byte("12llgaqqs3"), []byte("24fasd351"), []byte("safasfd")}
	s0 := signers[0].Sign(msgs[0], pkg)
	s1 := signers[1].Sign(msgs[1], pkg)
	s2 := signers[2].Sign(msgs[2], pkg)
	sigs := []*Signature{s0, s1, s2}
	aggSig, err := AggSig(sigs)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = aggSig.Serialize(&buf)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("total length: %v", len(buf.Bytes()))
	var newSig Signature
	err = newSig.Deserialize(&buf, pairing)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("s equals: %v\n", newSig.S.Equals(aggSig.S))
	fmt.Printf("t equals: %v\n", newSig.T.Equals(aggSig.T))
	fmt.Printf("w equals: %v\n", bytes.Equal(aggSig.w, newSig.w))
	fmt.Printf("total length: %v", len(buf.Bytes()))
}
