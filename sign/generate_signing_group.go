package sign

import (
	e "crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"

	errors "github.com/brandonbryant12/two_party_tss/errors"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
)

type FirstPartyItem struct {
	DerivationPath string
	Message        []byte
	PrivateKey     *e.PrivateKey
}

type RequestGroup struct {
	RandomNumber *big.Int
	PublicItems  []PublicItem
}

var curve = ec.S256()

func (fp Party1) GenerateGroupParameters(items []FirstPartyItem) (RequestGroup, error) {
	randomNumber, randomPoint, err := generateRandomPoint()
	if err != nil {
		return RequestGroup{}, errors.WrapError(err, errors.ErrCryptographicFailure, "generate group parameters failed")
	}

	publicItems := make([]PublicItem, len(items))
	for i, item := range items {
		encryptedPk, _ := fp.Pk.Encrypt(item.PrivateKey.D, rand.Reader)
		x, y := curve.ScalarBaseMult(item.PrivateKey.D.Bytes())
		publicKey := &e.PublicKey{
			X:     x,
			Y:     y,
			Curve: curve,
		}
		publicItems[i] = PublicItem{
			DerivationPath: item.DerivationPath,
			Message:        item.Message,
			RandomPoint:    randomPoint,
			PublicKey1:     publicKey,
			EncryptedPK1:   encryptedPk,
		}
	}
	return RequestGroup{
		RandomNumber: randomNumber,
		PublicItems:  publicItems,
	}, nil

}

func generateRandomPoint() (*big.Int, *e.PublicKey, error) {
	randomNumber, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random number: %w", err)
	}
	randomBytes := randomNumber.Bytes()
	x, y := curve.ScalarBaseMult(randomBytes)
	return randomNumber, &e.PublicKey{
		X:     x,
		Y:     y,
		Curve: curve,
	}, nil
}
