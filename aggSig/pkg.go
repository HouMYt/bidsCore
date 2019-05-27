package aggSig_pkg

import (
	"github.com/Nik-U/pbc"
	"math/big"
)

type PKG struct {
	Pairing   *pbc.Pairing
	secretKey *pbc.Element
	Generator *pbc.Element
	PublicKey *pbc.Element
}
type PubKeyPair struct {
	P0 *pbc.Element
	P1 *pbc.Element
}

//输出publickey
func (pkg *PKG) Gen(id []byte) PubKeyPair {
	g0 := pkg.Pairing.NewG1()
	g0.SetFromHash(append(id, big.NewInt(0).Bytes()...))
	g1 := pkg.Pairing.NewG1()
	g1.SetFromHash(append(id, big.NewInt(1).Bytes()...))
	P0 := pkg.Pairing.NewG1()
	P0.PowZn(g0, pkg.secretKey)
	P1 := pkg.Pairing.NewG1()
	P1.PowZn(g1, pkg.secretKey)
	return PubKeyPair{P0, P1}
}
