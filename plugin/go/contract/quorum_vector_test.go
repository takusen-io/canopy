package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"testing"

	drandbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign/bdn"
)

func TestBDNEIP2537CrossLanguageVector(t *testing.T) {
	privateKeys := []string{
		"6c275055a4f6ae6bccf1e6552e172c7b8cc538a7b8d2dd645125df9e25c9ed2d",
		"0add1e53f45d439b98182216a9215db238aaff12d1b057b3130b0c5e8e9b0b36",
	}
	suite := drandbls.NewBLS12381Suite()
	scheme := bdn.NewSchemeOnG2(suite)
	digest := sha256.Sum256([]byte("takusen bdn eip-2537 cross-language vector"))
	validators := make([]*Validator, len(privateKeys))
	signatures := make(map[string][]byte, len(privateKeys))
	for i, encoded := range privateKeys {
		raw, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		scalar := suite.G2().Scalar()
		if err = scalar.UnmarshalBinary(raw); err != nil {
			t.Fatal(err)
		}
		public := suite.G1().Point().Mul(scalar, suite.G1().Point().Base())
		publicBytes, err := public.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		addressHash := sha256.Sum256(publicBytes)
		address := append([]byte(nil), addressHash[:20]...)
		validators[i] = &Validator{Address: address, PublicKey: publicBytes, StakedAmount: 100}
		signature, err := scheme.Sign(scalar, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		signatures[hex.EncodeToString(address)] = signature
	}
	sort.Slice(validators, func(i, j int) bool {
		return string(validators[i].PublicKey) < string(validators[j].PublicKey)
	})
	message := &MessageSubmitQuorumSignature{
		ProofKind: "settlement", Digest: digest[:], Message: digest[:], ValidatorSetId: 1,
	}
	message.ProofId = quorumProofID(message.ProofKind, message.ValidatorSetId, message.Digest)
	proof, err := buildQuorumProof(42, message, validators, signatures, 200, 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.AggregateSignatureEip2537) != 256 || hex.EncodeToString(proof.SignerBitmap) != "03" {
		t.Fatalf("invalid exported proof shape: %+v", proof)
	}
	t.Logf("digest=%s", hex.EncodeToString(digest[:]))
	t.Logf("signature=%s", hex.EncodeToString(proof.AggregateSignatureEip2537))
}

func TestRequestFinalizationProofKindIsAllowed(t *testing.T) {
	if !allowedProofKinds["request-finalization"] {
		t.Fatal("request-finalization quorum certificates must be accepted")
	}
}
