package sign

import (
	e "crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"testing"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"

	"github.com/didiercrunch/paillier"
)

func TestPartialSignature(t *testing.T) {
	t.Run("TestPartialSignature", func(t *testing.T) {
		secondPartyItems := []SecondPartyItem{
			{
				PrivateKey: &e.PrivateKey{
					D: func() *big.Int {
						n, ok := new(big.Int).SetString("29466673249648374715134416906058786736501082843703534918849279921685210470848", 10)
						if !ok {
							t.Errorf("Invalid big.Int string")
						}
						return n
					}(),
				},
			},
			{
				PrivateKey: &e.PrivateKey{
					D: func() *big.Int {
						n, ok := new(big.Int).SetString("79999254988205839718088198878178983648988186857795183595873881692052685047744", 10)
						if !ok {
							t.Errorf("Invalid big.Int string")
						}
						return n
					}(),
				},
			},
		}
		paillierPubKey := &paillier.PublicKey{
			N: func() *big.Int {
				n, ok := new(big.Int).SetString("9b1efcabb3dbdbe5883fa207330b5270e128814426c07263b19cb48b27be30f349f89f06bb20d4ebe82999f728a098ba0ab95a508075bf92429629850079ac4546e493cd9fcdcdd0cd7fed20668e1d74866643fb9a8547a8216f4118ee6c7d93d902ac89f57c3ec73c1d43fa0b27f828daf67779bf3a82e1121f8f82fcff8fdd3e956dd818a4813e79e68800690db6b673ce81185fcce210dc61106a61830bafdb47de310398ec8bbfcd60c4844dbb2ec9b543298226e0fe6285829181f4ba2ddfe3b63b83a80076a84e093a746f849e627868c8aeff82fc8dffefcec3b85c70e8039f9607ca367181530f5da81704644898b94cf3861daded4f3036d6684245", 16)
				if !ok {
					t.Errorf("Invalid big.Int string")
				}
				return n
			}(),
		}

		m1, _ := hex.DecodeString("8280c82458c0e1520f183775a338b145cd0084111255f4fc0a061a20afa1d0c8")
		r1, _ := ec.PublicKeyFromString("02dafd1af5dac15e42ea96bc8475ddf6187a491578cec9c52e9cf8e04aa85c58fe")
		fp1, _ := ec.PublicKeyFromString("02dafd1af5dac15e42ea96bc8475ddf6187a491578cec9c52e9cf8e04aa85c58fe")

		m2, _ := hex.DecodeString("d78a482799fc02ead6b29c3b7b902364ed35d46536ed63be369a3d9b9f390599")
		r2, _ := ec.PublicKeyFromString("02dafd1af5dac15e42ea96bc8475ddf6187a491578cec9c52e9cf8e04aa85c58fe")
		fp2, _ := ec.PublicKeyFromString("02dafd1af5dac15e42ea96bc8475ddf6187a491578cec9c52e9cf8e04aa85c58fe")
		publicItems := []PublicItem{
			{
				DerivationPath: "m/1/18",
				Message:        m1,
				RandomPoint:    (*e.PublicKey)(r1),
				PublicKey1:     (*e.PublicKey)(fp1),
				EncryptedPK1:   CypherFromHexString("76d0faa4330aac7be051a4c2192f53c9f5fcec102731bb44bdd243195aeb0fb840518ae55546aa0a4837adbc0fa44361eb7461917f117ece88fb57b11c2a8e5e80cf8955300025b7db06a46eab997bd246026b6ce2d0f7c978c03e7b6b3dd913603585d01f69dc5f1a088e317d4f2a77169cec5ffc58de245bccd68d21286fbfd2f763eba0e4c3ab8bcd0ba5041e42409514bb3325999edb484056fe0ef6f7e6aeebde4e5865250493bcd8a793091d5f049358908314028fb07e9d918537e96f7b558e1512b2f9d6aaa59f4ecaedad045ea29c5273870dd6514c9246d954eedeb2079cb8d8b28865c9e48d6486c3902c1a792a306ea7bfb1b468a6f03eebd1fe65741416cb509047f321e5a86f9c55b236f0bf6e1e629f8725b40e42abf66ed51890406dc9307e68bd8480b03354b100293f1d5724b3dd6caaa8aec63eceeb2b6896b7942433992c39051d2f867be997577ee9de84b11bba95350c64a98f23f0bec7141254d89bfd89fda7db71a4735cd78e8476d63d0549b7a50c65e02f2d36ed79610fca315ef886d8060d0b1fbba34ef78764a4f054d87e9301dfbe9f816aa97e543f35a5dec7daeafb2037511a55aebd6c449cc9917689c45435bdebefacd02c54d84814542dc35adddf53b21a1bb287360ad8da1565d40078c1c48d18410df7704f384e75794a16ba4e9d2e1c70c6e0555f85b26b1b033ca3b2e10a0284"),
			},
			{
				DerivationPath: "m/1/19",
				Message:        m2,
				RandomPoint:    (*e.PublicKey)(r2),
				PublicKey1:     (*e.PublicKey)(fp2),
				EncryptedPK1:   CypherFromHexString("31bb44bdd243195aeb0fb840518ae55546aa0a76d0faa4330aac7be051a4c2192f53c9f5fcec1027edad045ea29c5273870dd6514c9246d954eedeb2079cb8d8b28865c9e48d6486c3902c1a792a306ea7bfb1b468a6f03eebd1fe65741416cb509047f321e5a86f9c55b236f0bf6e1e629f8725b40e42abf66ed51890406dc9307e68bd8480b03354b100293f1d5724b3dd6caaa8aec63eceeb2b6896b7942433992c39051d2f867be997577ee9de84b11bba95350c64a98f23f0bec7141254d89bfd89fda7db71a4735cd78e9edb484056fe0ef6f7e6aeebde4e5865250493bcd8a793091d5f049358908314028fb07e9d918537e96f7b558e1512b2f9d6aaa59f4eca8476d63d0549b7a50c65e02f2d36ed79610fca315ef886d8060d0b1fbba34ef78764a4f054d87e9301dfbe9f816aa97e543f35a5dec7dac45435bdebefacd02c54d84814542dc35adddf53b21a1bb287360ad8da1565d40078c1c48d1841e10a0df7704f384e75794a16ba4e9d2e4837adbc0fa44361eb7461917f117ece88fb57b11c2a8e5e80cf8955300025b7db06a46eab997bd246026b6ce2d0f7c978c03e7b6b3dd913603585d01f69dc5f1a088e317d4f2a77169cec5ffc58de245bccd68d21286fbfd2f763eba0e4c3ab8bcd0ba5041e42409514bb332599eafb2037511a55aebd6c449cc99176896b1b555fc6e0a3b21c7085b20284033c"),
			},
		}

		sp := &Party2{}

		sigs, err := sp.GetPartialSignatures(paillierPubKey, secondPartyItems, publicItems)
		if err != nil {
			t.Errorf("Error getting partial signatures: %v", err)
		}

		for i, partialSig := range sigs {
			pubKey := (*ec.PublicKey)(partialSig.PublicKey)
			if pubKey.ToDER() == "" {
				t.Errorf("Expected partial signature %d to have a non-empty public key", i)
			}
			if partialSig.R == "" {
				t.Errorf("Expected partial signature %d to have a non-empty R value", i)
			}
			if partialSig.PartialS == "" {
				t.Errorf("Expected partial signature %d to have a non-empty partial S value", i)
			}
		}

	})
}
