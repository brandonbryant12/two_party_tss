package sign

import (
	e "crypto/ecdsa"
	"encoding/hex"
	"math/big"

	phe "github.com/brandonbryant12/two_party_tss/phe"

	"github.com/didiercrunch/paillier"
)

type PublicItem struct {
	DerivationPath string
	Message        []byte
	RandomPoint    *e.PublicKey
	PublicKey1     *e.PublicKey
	EncryptedPK1   *paillier.Cypher
}

type Signer1 interface {
	GenerateGroupParameters(signatureRequestItems []FirstPartyItem) (RequestGroup, error)
	CompleteSignatures(ps []PartialSignature, rg RequestGroup) ([]CompleteSignature, error)
	GetPaillierPublicKey() *paillier.PublicKey
}

type Party1 struct {
	Pk *paillier.PrivateKey
}

type Signer2 interface {
	GetPartialSignatures(pubKey *paillier.PublicKey, publicItems []PublicItem) ([]PartialSignature, error)
}

type Party2 struct{}

type TSS struct {
	s Signer2
	f Signer1
}

func (tss *TSS) Sign(items []FirstPartyItem) ([]CompleteSignature, error) {
	group, err := tss.f.GenerateGroupParameters(items)
	if err != nil {
		return nil, err
	}
	partialSignatures, err := tss.s.GetPartialSignatures(tss.f.GetPaillierPublicKey(), group.PublicItems)
	if err != nil {
		return nil, err
	}
	completedSignatures, err := tss.f.CompleteSignatures(partialSignatures, group)
	if err != nil {
		return nil, err
	}
	return completedSignatures, nil
}

func (fp *Party1) GetPaillierPublicKey() *paillier.PublicKey {
	return &fp.Pk.PublicKey
}

func NewFirstParty() (*Party1, error) {
	pk, err := phe.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &Party1{
		Pk: pk.PrivateKey,
	}, nil
}

func CypherFromHexString(hexString string) *paillier.Cypher {
	cypherBytes, _ := hex.DecodeString(hexString)
	cypherBigInt := new(big.Int).SetBytes(cypherBytes)
	return &paillier.Cypher{C: cypherBigInt}
}
