package ecdsa

import (
	e "crypto/ecdsa"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func GetSharedPoint(party1Private *e.PrivateKey, party2Public *e.PublicKey) *e.PublicKey {
	commonPointX, commonPointY := secp256k1.S256().ScalarMult(party2Public.X, party2Public.Y, party1Private.D.Bytes())
	return &e.PublicKey{
		Curve: secp256k1.S256(),
		X:     commonPointX,
		Y:     commonPointY,
	}
}
