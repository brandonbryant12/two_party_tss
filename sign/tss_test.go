package sign

import (
	e "crypto/ecdsa"
	"math/big"
	"testing"
)

func TestSign(t *testing.T) {
	t.Run("TestSign a bitcoin message", func(t *testing.T) {
		// pk1 49982963557714327503794127502838260592498489790368914502916893040465202760255 int
		// pk2 95809605156339102684634422900634864609520414428962836353868771273875130775213
		fp, err := NewFirstParty()
		if err != nil {
			t.Errorf("Error creating first party: %v", err)
		}
		sp := &Party2{}
		pk1 := &e.PrivateKey{D: func() *big.Int {
			i, _ := new(big.Int).SetString("49982963557714327503794127502838260592498489790368914502916893040465202760255", 10)
			return i
		}()}

		pk2 := &e.PrivateKey{D: func() *big.Int {
			i, _ := new(big.Int).SetString("95809605156339102684634422900634864609520414428962836353868771273875130775213", 10)
			return i
		}()}
		fpItems := []FirstPartyItem{
			{
				DerivationPath: "m/1/18",
				Message:        []byte("37c8dbe24e14073958444f45db5b34c4496e87019ab9ce4ce06821c516b5c02d"),
				PrivateKey:     pk1,
			},
		}

		groupParams, err := fp.GenerateGroupParameters(fpItems)
		if err != nil {
			t.Errorf("Error generating group parameters: %v", err)
		}

		spItems := []SecondPartyItem{
			{
				PrivateKey: pk2,
			},
		}
		partialSigs, err := sp.GetPartialSignatures(fp.GetPaillierPublicKey(), spItems, groupParams.PublicItems)
		if err != nil {
			t.Errorf("Error getting partial signatures: %v", err)
		}

		completeSigs, err := fp.CompleteSignatures(partialSigs, groupParams)
		if err != nil {
			t.Errorf("Error completing signatures: %v", err)
		}
		for _, sig := range completeSigs {
			if sig.Signature == nil {
				t.Errorf("Signature is nil")
			}
			if sig.PublicKey == nil {
				t.Errorf("Public key is nil")
			}
			if sig.R == "" {
				t.Errorf("R is empty")
			}
		}

	})

}
