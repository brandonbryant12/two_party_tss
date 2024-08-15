package sign

import (
	"encoding/hex"
	"fmt"
	"math/big"

	e "crypto/ecdsa"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
	errors "github.com/brandonbryant12/two_party_tss/errors"
	"github.com/didiercrunch/paillier"
)

type CompleteSignature struct {
	PublicKey *ec.PublicKey
	R         string
	Signature *ec.Signature
}

func (fp Party1) CompleteSignatures(ps []PartialSignature, rg RequestGroup) ([]CompleteSignature, error) {
	if len(ps) != len(rg.PublicItems) {
		return nil, errors.WrapError(fmt.Errorf("number of partial signatures does not match number of public items"), errors.ErrInvalidInput, "Complete signature failuer")
	}
	sigs := make([]CompleteSignature, len(ps))
	for i, partial := range ps {
		s, err := generateSignature(partial, fp.Pk, rg)
		if err != nil {
			return nil, errors.WrapError(err, errors.ErrCryptographicFailure, "Failed to generate signature")
		}
		fmt.Println(string(rg.PublicItems[i].Message))
		der, _ := s.Signature.ToDER()
		fmt.Println(hex.EncodeToString(der))
		verified := s.Verify(rg.PublicItems[i].Message)
		if !verified {
			return nil, errors.WrapError(err, errors.ErrCryptographicFailure, "Signature verification failed")
		}
		sigs[i] = s
	}
	return sigs, nil
}

func generateSignature(ps PartialSignature, pk *paillier.PrivateKey, rg RequestGroup) (CompleteSignature, error) {
	psHex := new(big.Int)
	psHex.SetString(ps.PartialS, 16)
	cipher := paillier.Cypher{
		C: psHex,
	}
	decryptedPartialS := pk.Decrypt(&cipher)
	randomNumber := new(big.Int).ModInverse(rg.RandomNumber, curve.N)
	s := new(big.Int).Mul(decryptedPartialS, randomNumber)
	s.Mod(s, curve.N)
	ensureLowS(s)
	sBytes := s.Bytes()
	sBytes = ensureNoExcessivePaddingS(sBytes)
	rBytes, err := hex.DecodeString(ps.R)
	if err != nil {
		return CompleteSignature{}, errors.WrapError(err, errors.ErrInvalidInput, err.Error())
	}

	return CompleteSignature{
		PublicKey: (*ec.PublicKey)(ps.PublicKey),
		R:         ps.R,
		Signature: &ec.Signature{
			R: new(big.Int).SetBytes(rBytes),
			S: new(big.Int).SetBytes(sBytes),
		},
	}, nil

}

func ensureLowS(s *big.Int) *big.Int {
	halfN := new(big.Int).Rsh(curve.N, 1)
	if s.Cmp(halfN) > 0 {
		s.Sub(ec.S256().N, s)
	}
	return s
}
func ensureNoExcessivePaddingS(s []byte) []byte {
	for len(s) > 1 && s[0] == 0x00 && (s[1]&0x80) == 0 {
		s = s[1:]
	}
	return s
}

func (s *CompleteSignature) Verify(msg []byte) bool {
	pubKey := &e.PublicKey{
		Curve: curve,
		X:     s.PublicKey.X,
		Y:     s.PublicKey.Y,
	}
	return e.Verify(pubKey, msg, s.Signature.R, s.Signature.S)
}
