package contract

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

var nitroFixtureTime = time.Unix(1_800_000_000, 0).UTC()

type nitroFixture struct {
	message *MessageRegisterServicer
	rootDER []byte
	pcr0    []byte
	pcr1    []byte
	pcr2    []byte
}

func newNitroFixture(t *testing.T, attestedAt time.Time, owner []byte) nitroFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x41}, 32)
	userData := registrationUserData(owner)
	keyDigest := sha256.Sum256(publicKey)
	params := defaultProtocolParams()
	message := &MessageRegisterServicer{
		OwnerAddress: owner, TeeKeyId: "ed25519:" + hex.EncodeToString(keyDigest[:]), PublicKey: publicKey,
		Nonce: nonce, UserData: userData, EvmPayoutAddress: append([]byte(nil), owner...), Models: []string{"model"}, Bond: params.MinimumServicerBond,
	}
	registrationDigest := sha256.New()
	_, _ = registrationDigest.Write([]byte("takusen:nitro-registration\x00"))
	_, _ = registrationDigest.Write(nonce)
	_, _ = registrationDigest.Write([]byte{0})
	_, _ = registrationDigest.Write(userData)
	message.ProofSignature = ed25519.Sign(privateKey, registrationDigest.Sum(nil))

	rootKey := mustP384Key(t)
	intermediateKey := mustP384Key(t)
	leafKey := mustP384Key(t)
	validFrom, validUntil := attestedAt.Add(-24*time.Hour), attestedAt.Add(24*time.Hour)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Governed Nitro Root"},
		NotBefore: validFrom, NotAfter: validUntil, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Nitro Intermediate"},
		NotBefore: validFrom, NotAfter: validUntil, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Nitro Attestation"},
		NotBefore: validFrom, NotAfter: validUntil, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	pcr0, pcr1, pcr2 := bytes.Repeat([]byte{1}, 48), bytes.Repeat([]byte{2}, 48), bytes.Repeat([]byte{3}, 48)
	document := nitroDocument{
		ModuleID: "fixture-module", Digest: "SHA384", TimestampMS: uint64(attestedAt.UnixMilli()),
		PCRs: map[uint][]byte{0: pcr0, 1: pcr1, 2: pcr2}, Certificate: leafDER,
		CABundle: [][]byte{intermediateDER, rootDER}, PublicKey: publicKey, UserData: userData, Nonce: nonce,
	}
	payload, err := cbor.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := cbor.Marshal(map[int]int{1: -35})
	if err != nil {
		t.Fatal(err)
	}
	sigStructure, err := cbor.Marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384(sigStructure)
	r, s, err := ecdsa.Sign(rand.Reader, leafKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 96)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])
	message.AttestationDocument, err = cbor.Marshal(cbor.Tag{Number: 18, Content: []any{protected, map[string]any{}, payload, signature}})
	if err != nil {
		t.Fatal(err)
	}
	return nitroFixture{message: message, rootDER: rootDER, pcr0: pcr0, pcr1: pcr1, pcr2: pcr2}
}

func mustP384Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testNitroRoot(t *testing.T) []byte {
	t.Helper()
	return newNitroFixture(t, nitroFixtureTime, bytes.Repeat([]byte{7}, 20)).rootDER
}

func protocolParamsForNitroFixture(fixture nitroFixture) *ProtocolParams {
	params := defaultProtocolParams()
	params.Revision = 1
	params.NitroTrustRoot = append([]byte(nil), fixture.rootDER...)
	params.ApprovedPcrs = []*PCRPolicy{{Pcr0: fixture.pcr0, Pcr1: fixture.pcr1, Pcr2: fixture.pcr2, Active: true}}
	return params
}

func TestRegisterServicerAtomicallyValidatesEvidenceBondsAndActivates(t *testing.T) {
	contract, store, owner, _ := newMemoryContract(t)
	fixture := newNitroFixture(t, nitroFixtureTime, owner)
	params := protocolParamsForNitroFixture(fixture)
	params.Models = []*ModelParams{{Model: "model", Provider: "provider", Active: true}}
	params.DefaultModels = []string{"model"}
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForAccount(owner), &Account{Address: owner, Amount: 100})
	blockMicros := uint64(nitroFixtureTime.Add(time.Minute).UnixMicro())
	if signer, err := checkRegisterServicer(fixture.message); err != nil || !bytes.Equal(signer, owner) {
		t.Fatalf("registration check signer=%x err=%v", signer, err)
	}
	if response := contract.deliverRegisterServicer(10, blockMicros, fixture.message); response.Error != nil {
		t.Fatal(response.Error)
	}
	if _, found := store.values[string(KeyForEnclave(fixture.message.TeeKeyId))]; !found {
		t.Fatal("atomic registration did not commit the enclave key")
	}
	servicer := new(Servicer)
	if err := Unmarshal(store.values[string(KeyForServicer(owner))], servicer); err != nil || servicer.Bond != fixture.message.Bond || !servicer.Active {
		t.Fatalf("atomic registration did not commit the bonded servicer: servicer=%+v err=%v", servicer, err)
	}
	eligible, err := contract.eligibleServicers("model")
	if err != nil || len(eligible) != 1 || !bytes.Equal(selectServicer([]byte("input"), []byte("anchor"), "model", eligible).OwnerAddress, owner) {
		t.Fatalf("registered enclave did not become assignable: eligible=%d err=%v", len(eligible), err)
	}
	if response := contract.deliverRegisterServicer(11, blockMicros, fixture.message); response.Error == nil {
		t.Fatal("initial registration accepted an existing servicer owner")
	}
}

func TestManageServicerAtomicallyRotatesEnclave(t *testing.T) {
	contract, store, owner, _ := newMemoryContract(t)
	initial := newNitroFixture(t, nitroFixtureTime, owner)
	params := protocolParamsForNitroFixture(initial)
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForAccount(owner), &Account{Address: owner, Amount: params.MinimumServicerBond})
	blockMicros := uint64(nitroFixtureTime.Add(time.Minute).UnixMicro())
	if response := contract.deliverRegisterServicer(10, blockMicros, initial.message); response.Error != nil {
		t.Fatal(response.Error)
	}

	replacement := newNitroFixture(t, nitroFixtureTime.Add(time.Minute), owner)
	params = protocolParamsForNitroFixture(replacement)
	store.put(t, KeyForProtocolParams(), params)
	manage := &MessageManageServicer{
		OwnerAddress: owner, ExpectedRevision: 1,
		Rotation: &EnclaveRotation{
			TeeKeyId: replacement.message.TeeKeyId, PublicKey: replacement.message.PublicKey,
			Nonce: replacement.message.Nonce, UserData: replacement.message.UserData,
			ProofSignature: replacement.message.ProofSignature, AttestationDocument: replacement.message.AttestationDocument,
		},
	}
	malformed := proto.Clone(manage).(*MessageManageServicer)
	malformed.Rotation.AttestationDocument = append([]byte(nil), manage.Rotation.AttestationDocument...)
	malformed.Rotation.AttestationDocument[len(malformed.Rotation.AttestationDocument)-1] ^= 1
	if response := contract.deliverManageServicer(11, uint64(nitroFixtureTime.Add(2*time.Minute).UnixMicro()), malformed); response.Error == nil {
		t.Fatal("malformed replacement attestation was accepted")
	}
	oldKey := new(EnclaveKey)
	if found, err := contract.read(KeyForEnclave(initial.message.TeeKeyId), oldKey); err != nil || !found || oldKey.Status != "active" {
		t.Fatalf("failed rotation changed the old enclave: found=%v key=%+v err=%v", found, oldKey, err)
	}
	if found, err := contract.read(KeyForEnclave(replacement.message.TeeKeyId), new(EnclaveKey)); err != nil || found {
		t.Fatalf("failed rotation committed the replacement enclave: found=%v err=%v", found, err)
	}

	if response := contract.deliverManageServicer(11, uint64(nitroFixtureTime.Add(2*time.Minute).UnixMicro()), manage); response.Error != nil {
		t.Fatal(response.Error)
	}
	newKey := new(EnclaveKey)
	servicer := new(Servicer)
	if found, err := contract.read(KeyForEnclave(initial.message.TeeKeyId), oldKey); err != nil || !found || oldKey.Status != "draining" {
		t.Fatalf("rotation did not retire the old enclave: found=%v key=%+v err=%v", found, oldKey, err)
	}
	if found, err := contract.read(KeyForEnclave(replacement.message.TeeKeyId), newKey); err != nil || !found || newKey.Status != "active" {
		t.Fatalf("rotation did not register the replacement enclave: found=%v key=%+v err=%v", found, newKey, err)
	}
	if found, err := contract.read(KeyForServicer(owner), servicer); err != nil || !found || !servicer.Active || servicer.TeeKeyId != replacement.message.TeeKeyId {
		t.Fatalf("rotation did not atomically switch the servicer: found=%v servicer=%+v err=%v", found, servicer, err)
	}
}

func TestRegisterServicerWithAttestationIsFeePayingAndOwnerSigned(t *testing.T) {
	contract, _, owner, _ := newMemoryContract(t)
	fixture := newNitroFixture(t, nitroFixtureTime, owner)
	wrapped, err := anypb.New(fixture.message)
	if err != nil {
		t.Fatal(err)
	}
	request := &PluginCheckRequest{Tx: &Transaction{Fee: 1, Msg: wrapped}}
	response := contract.CheckTx(request)
	if response.Error != nil || len(response.AuthorizedSigners) != 1 || !bytes.Equal(response.AuthorizedSigners[0], owner) {
		t.Fatalf("fee-paying registration signer=%x err=%v", response.AuthorizedSigners, response.Error)
	}
	request.Tx.Fee = 0
	if response = contract.CheckTx(request); response.Error == nil {
		t.Fatal("zero-fee atomic servicer registration was accepted")
	}
}

func TestRegisterServicerRejectsMalformedStaleFutureRootPCRAndBindings(t *testing.T) {
	owner := bytes.Repeat([]byte{7}, 20)
	valid := newNitroFixture(t, nitroFixtureTime, owner)
	blockMicros := uint64(nitroFixtureTime.Add(time.Minute).UnixMicro())
	if _, err := verifyNitroRegistration(valid.message, valid.rootDER, blockMicros); err != nil {
		t.Fatal(err)
	}
	malformed := *valid.message
	malformed.AttestationDocument = append([]byte(nil), valid.message.AttestationDocument...)
	malformed.AttestationDocument[len(malformed.AttestationDocument)-1] ^= 1
	if _, err := verifyNitroRegistration(&malformed, valid.rootDER, blockMicros); err == nil {
		t.Fatal("malformed evidence was accepted")
	}
	for name, fixture := range map[string]nitroFixture{
		"stale":  newNitroFixture(t, nitroFixtureTime.Add(-10*time.Minute), owner),
		"future": newNitroFixture(t, nitroFixtureTime.Add(3*time.Minute), owner),
	} {
		if _, err := verifyNitroRegistration(fixture.message, fixture.rootDER, blockMicros); err == nil {
			t.Fatalf("%s evidence was accepted", name)
		}
	}
	wrongRoot := newNitroFixture(t, nitroFixtureTime, owner)
	if _, err := verifyNitroRegistration(valid.message, wrongRoot.rootDER, blockMicros); err == nil {
		t.Fatal("evidence chaining to a different root was accepted")
	}
	wrongOwner := *valid.message
	wrongOwner.OwnerAddress = bytes.Repeat([]byte{8}, 20)
	if _, err := checkRegisterServicer(&wrongOwner); err == nil {
		t.Fatal("owner-bound user data was accepted for another owner")
	}
	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := *valid.message
	wrongKey.PublicKey = otherPublic
	keyDigest := sha256.Sum256(otherPublic)
	wrongKey.TeeKeyId = "ed25519:" + hex.EncodeToString(keyDigest[:])
	registrationDigest := sha256.New()
	_, _ = registrationDigest.Write([]byte("takusen:nitro-registration\x00"))
	_, _ = registrationDigest.Write(wrongKey.Nonce)
	_, _ = registrationDigest.Write([]byte{0})
	_, _ = registrationDigest.Write(wrongKey.UserData)
	wrongKey.ProofSignature = ed25519.Sign(otherPrivate, registrationDigest.Sum(nil))
	if _, err := verifyNitroRegistration(&wrongKey, valid.rootDER, blockMicros); err == nil {
		t.Fatal("attestation was accepted for a different enclave key")
	}
	params := protocolParamsForNitroFixture(valid)
	params.ApprovedPcrs[0].Pcr2 = bytes.Repeat([]byte{9}, 48)
	contract, store, _, _ := newMemoryContract(t)
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForAccount(owner), &Account{Address: owner, Amount: valid.message.Bond})
	if response := contract.deliverRegisterServicer(10, blockMicros, valid.message); response.Error == nil {
		t.Fatal("registration with an unapproved PCR tuple was accepted")
	}
	oversized := *valid.message
	oversized.AttestationDocument = make([]byte, maxNitroAttestationSize+1)
	if _, err := checkRegisterServicer(&oversized); err == nil {
		t.Fatal("oversized evidence was accepted")
	}
}

func TestRegisterServicerHistoricalReplayIsDeterministic(t *testing.T) {
	first, firstStore, owner, _ := newMemoryContract(t)
	second, secondStore, _, _ := newMemoryContract(t)
	fixture := newNitroFixture(t, nitroFixtureTime, owner)
	params := protocolParamsForNitroFixture(fixture)
	firstStore.put(t, KeyForProtocolParams(), params)
	secondStore.put(t, KeyForProtocolParams(), params)
	firstStore.put(t, KeyForAccount(owner), &Account{Address: owner, Amount: fixture.message.Bond})
	secondStore.put(t, KeyForAccount(owner), &Account{Address: owner, Amount: fixture.message.Bond})
	blockMicros := uint64(nitroFixtureTime.Add(time.Minute).UnixMicro())
	if response := first.deliverRegisterServicer(77, blockMicros, fixture.message); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := second.deliverRegisterServicer(77, blockMicros, fixture.message); response.Error != nil {
		t.Fatal(response.Error)
	}
	key := string(KeyForEnclave(fixture.message.TeeKeyId))
	if !bytes.Equal(firstStore.values[key], secondStore.values[key]) {
		t.Fatal("historical replay produced different enclave state")
	}
}

func TestRegisterServicerFailsClosedWithoutGovernedVerificationState(t *testing.T) {
	contract, store, owner, _ := newMemoryContract(t)
	fixture := newNitroFixture(t, nitroFixtureTime, owner)
	delete(store.values, string(KeyForProtocolParams()))
	if response := contract.deliverRegisterServicer(10, uint64(nitroFixtureTime.UnixMicro()), fixture.message); response.Error == nil {
		t.Fatal("registration was accepted without governed Nitro root and PCR state")
	}
}
