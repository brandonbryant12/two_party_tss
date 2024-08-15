package phe

import (
	"crypto/rand"
	"fmt"
	"math/big"

	paillier "github.com/didiercrunch/paillier"
)

type PaillierPrivateKey struct {
	P *big.Int
	Q *big.Int
	*paillier.PrivateKey
}

func GenerateKey() (*PaillierPrivateKey, error) {
	keysize := 1024
	p, err := generatePrime(keysize / 2)
	if err != nil {
		return nil, fmt.Errorf("failed to generate prime: %w", err)
	}
	q, err := generatePrime(keysize / 2)
	if err != nil {
		return nil, fmt.Errorf("failed to generate prime: %w", err)
	}

	for p == q {
		q, err = generatePrime(keysize / 2)
		if err != nil {
			return nil, fmt.Errorf("failed to generate prime: %w", err)
		}
	}

	return &PaillierPrivateKey{
		P:          p,
		Q:          q,
		PrivateKey: paillier.CreatePrivateKey(p, q),
	}, nil
}

func generatePrime(n int) (*big.Int, error) {
	p, err := rand.Prime(rand.Reader, n)
	if err != nil {
		return nil, fmt.Errorf("failed to generate prime: %w", err)
	}
	return p, nil
}

type KeyPair struct {
	PrivateKey struct {
		P string `json:"p"`
		Q string `json:"q"`
	} `json:"paillierPrivateKey"`
	PublicKey string `json:"paillierPublicKey"`
}

func (k *PaillierPrivateKey) ToKeyPair() KeyPair {
	return KeyPair{
		PrivateKey: struct {
			P string `json:"p"`
			Q string `json:"q"`
		}{
			P: k.P.String(),
			Q: k.Q.String(),
		},
		PublicKey: k.PublicKey.N.String(),
	}
}
