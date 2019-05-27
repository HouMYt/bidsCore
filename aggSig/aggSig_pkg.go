package aggSig_pkg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Nik-U/pbc"
	"io"
	"math/big"
	"time"
)
const AggSiglength = 35
const wlength = 19
const ellength = 8


type Signer struct {
	ID      []byte
	pkPair  PubKeyPair
	pairing *pbc.Pairing
}
type Signature struct {
	w       []byte
	S       *pbc.Element
	T       *pbc.Element
	pairing *pbc.Pairing
}

func (*Signer) Getw() []byte {
	return []byte(time.RFC822)
}
func (signer *Signer) Sign(msg []byte, pkg *PKG) *Signature {
	w := signer.Getw()
	Pw := signer.pairing.NewG1()
	Pw.SetFromHash(w)
	c := signer.pairing.NewZr()
	var temphash []byte
	temphash = append(msg, signer.ID...)
	temphash = append(temphash, w...)
	c.SetFromHash(temphash)
	r := signer.pairing.NewZr()
	r.Rand()
	t := signer.pairing.NewG2()
	t.PowZn(pkg.Generator, r)
	temp1 := signer.pairing.NewG1()
	temp1.PowZn(Pw, r)
	temp2 := signer.pairing.NewG1()
	temp2.PowZn(signer.pkPair.P1, c)
	sig := signer.pairing.NewG1()
	sig.Mul(temp1, signer.pkPair.P0)
	sig.Mul(sig, temp2)
	return &Signature{
		S:       sig,
		w:       w,
		T:       t,
		pairing: signer.pairing,
	}
}
func AggSig(sigs []*Signature) (*Signature, error) {
	if len(sigs) == 0 {
		return nil, errors.New("must be one or more than one signatures")
	}
	sig := sigs[0]
	for i := 1; i < len(sigs); i++ {
		if !bytes.Equal(sig.w, sigs[i].w) {
			return nil, errors.New("signatures must have the same w")
		}
		sig.S.Mul(sig.S, sigs[i].S)
		sig.T.Mul(sig.T, sigs[i].T)
	}
	return sig, nil
}
func Verify(sig *Signature, id [][]byte, msg [][]byte, pkg *PKG) (bool, error) {
	if len(id) != len(msg) {
		return false, errors.New("id and msg array must be same amount")

	}
	if len(id) == 0 {
		return false, errors.New("id and msg array must have one or more elements")
	}
	left := sig.pairing.NewGT()
	left.Pair(sig.S, pkg.Generator)
	pw := sig.pairing.NewG1()
	pw.SetFromHash(sig.w)
	g0 := pkg.Pairing.NewG1()
	g0.SetFromHash(append(id[0], big.NewInt(0).Bytes()...))
	aggP0 := g0
	g1 := pkg.Pairing.NewG1()
	g1.SetFromHash(append(id[0], big.NewInt(1).Bytes()...))
	aggP1 := g0
	c := sig.pairing.NewZr()
	var temphash []byte
	cP := sig.pairing.NewG1()
	temphash = append(msg[0], id[0]...)
	temphash = append(temphash, sig.w...)
	c.SetFromHash(temphash)
	aggP1.PowZn(aggP1, c)
	for i := 1; i < len(id); i++ {
		aggP0.Mul(aggP0, g0.SetFromHash(append(id[i], big.NewInt(0).Bytes()...)))
		temphash = append(msg[i], id[i]...)
		temphash = append(temphash, sig.w...)
		c.SetFromHash(temphash)
		cP.PowZn(g1.SetFromHash(append(id[i], big.NewInt(1).Bytes()...)), c)
		aggP1.Mul(aggP1, cP)
	}
	right := sig.pairing.NewGT()
	right0 := sig.pairing.NewGT()
	right1 := sig.pairing.NewGT()
	right0.Pair(pw, sig.T)
	right1.Pair(aggP0.Mul(aggP0, aggP1), pkg.PublicKey)
	right.ProdPair(pw, sig.T, aggP0.Mul(aggP0, aggP1), pkg.PublicKey)
	//right.Mul(right0,right1)
	fmt.Printf("right0 %v \n", left.Equals(right0))
	fmt.Printf("right1 %v \n", left.Equals(right1))
	if left.Equals(right) {
		return true, nil
	}
	return false, errors.New("false")
}
func (s *Signature) Serialize(w io.Writer) error {
	return writeAggSig(w, s)
}
func (s *Signature) Deserialize(r io.Reader, pairing *pbc.Pairing) error {
	return readAggSig(r, s, pairing)
}
func Deserialize(sigmsg [AggSiglength]byte, pkg *PKG) (*Signature, error) {
	var sig Signature
	var msg []byte
	copy(msg, sigmsg[:])
	err := json.Unmarshal(msg, sig)
	if err != nil {
		return nil, err
	}
	sig.pairing = pkg.Pairing
	return &sig, nil

}
