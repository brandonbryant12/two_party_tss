package sign

import (
	e "crypto/ecdsa"
	"crypto/rand"
	"math/big"

	"github.com/didiercrunch/paillier"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type PartialSignature struct {
	R         string       `json:"r" validate:"required"`
	PublicKey *e.PublicKey `json:"publicKey" validate:"required"`
	PartialS  string       `json:"partialSignature" validate:"required"`
}

type SecondPartyItem struct {
	PrivateKey *e.PrivateKey
}

func (sp *Party2) GetPartialSignatures(paillerPubKey *paillier.PublicKey, items []SecondPartyItem, publicItems []PublicItem) ([]PartialSignature, error) {
	partialSignatures := make([]PartialSignature, len(items))
	for i, item := range items {
		r, inverseRandom := findRValue(publicItems[i].RandomPoint)
		partialS := r.Mul(r, item.PrivateKey.D)
		cipher := paillerPubKey.Mul(publicItems[0].EncryptedPK1, partialS)

		encryptedScaler, _ := paillerPubKey.Encrypt(new(big.Int).SetBytes(publicItems[i].Message), rand.Reader)

		cipher = paillerPubKey.Add(cipher, encryptedScaler)
		cipher = paillerPubKey.Mul(cipher, inverseRandom)

		publicX, publicY := curve.ScalarMult(publicItems[i].PublicKey1.X, publicItems[i].PublicKey1.Y, item.PrivateKey.D.Bytes())
		pubKey := &e.PublicKey{
			X:     publicX,
			Y:     publicY,
			Curve: curve,
		}
		partialSignatures[i] = PartialSignature{
			R:         r.Text(16),
			PublicKey: pubKey,
			PartialS:  cipher.C.Text(16),
		}
	}
	return partialSignatures, nil
}

func generateRandomNumber() *big.Int {
	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	randomNumber := new(big.Int).SetBytes(randomBytes)
	return randomNumber
}

func findRValue(randomPoint *e.PublicKey) (r, invRandomNumber *big.Int) {
	r, randomNumber, invRandomNumber := new(big.Int), new(big.Int), new(big.Int)
	isRNegative := true
	for isRNegative {
		randomNumber = generateRandomNumber()
		randomNumber.Mod(randomNumber, secp256k1.S256().N)
		commonRandomX, _ := secp256k1.S256().ScalarMult(randomPoint.X, randomPoint.Y, randomNumber.Bytes())
		r = r.Mod(commonRandomX, secp256k1.S256().N)
		isRNegative = len(r.Bytes()) > 32
	}
	invRandomNumber = new(big.Int).ModInverse(randomNumber, secp256k1.S256().N)
	return r, invRandomNumber
}
