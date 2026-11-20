package contract

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"math"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	maxNitroAttestationSize = 16 << 10
	maxNitroCertificateSize = 4 << 10
	maxNitroCABundleEntries = 8
	maxNitroModuleIDSize    = 256
	nitroMaxAgeMillis       = uint64((5 * time.Minute) / time.Millisecond)
	nitroMaxFutureMillis    = uint64(time.Minute / time.Millisecond)
)

type nitroDocument struct {
	ModuleID    string          `cbor:"module_id"`
	Digest      string          `cbor:"digest"`
	TimestampMS uint64          `cbor:"timestamp"`
	PCRs        map[uint][]byte `cbor:"pcrs"`
	Certificate []byte          `cbor:"certificate"`
	CABundle    [][]byte        `cbor:"cabundle"`
	PublicKey   []byte          `cbor:"public_key"`
	UserData    []byte          `cbor:"user_data"`
	Nonce       []byte          `cbor:"nonce"`
}

func verifyNitroRegistration(message *MessageRegisterServicer, rootDER []byte, timeMicros uint64) (nitroDocument, *PluginError) {
	if message == nil || timeMicros == 0 || timeMicros > math.MaxInt64 || len(rootDER) == 0 || len(rootDER) > maxNitroCertificateSize {
		return nitroDocument{}, ErrUnauthorized("governed Nitro verification context is invalid")
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil || !bytes.Equal(root.Raw, rootDER) || !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nitroDocument{}, ErrUnauthorized("governed Nitro trust root is invalid")
	}
	mode, err := cbor.DecOptions{
		TagsMd: cbor.TagsAllowed, DupMapKey: cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels: 8, MaxArrayElements: 32, MaxMapPairs: 32, IndefLength: cbor.IndefLengthAllowed,
	}.DecMode()
	if err != nil {
		return nitroDocument{}, ErrState("initialize bounded Nitro CBOR decoder")
	}
	sign1, err := decodeNitroCOSESign1(mode, message.AttestationDocument)
	if err != nil {
		return nitroDocument{}, ErrCrypto(err.Error())
	}
	var protected, payload, signature []byte
	if err = mode.Unmarshal(sign1[0], &protected); err != nil {
		return nitroDocument{}, ErrCrypto("invalid Nitro protected headers")
	}
	var protectedHeaders map[int64]int64
	if err = mode.Unmarshal(protected, &protectedHeaders); err != nil || len(protectedHeaders) != 1 || protectedHeaders[1] != -35 {
		return nitroDocument{}, ErrCrypto("Nitro attestation must use COSE ES384")
	}
	var unprotectedHeaders map[int64]cbor.RawMessage
	if err = mode.Unmarshal(sign1[1], &unprotectedHeaders); err != nil || len(unprotectedHeaders) != 0 {
		return nitroDocument{}, ErrCrypto("Nitro attestation has unsupported unprotected headers")
	}
	if err = mode.Unmarshal(sign1[2], &payload); err != nil || len(payload) == 0 || len(payload) > maxNitroAttestationSize {
		return nitroDocument{}, ErrCrypto("invalid Nitro attestation payload")
	}
	if err = mode.Unmarshal(sign1[3], &signature); err != nil || len(signature) != 96 {
		return nitroDocument{}, ErrCrypto("invalid Nitro COSE signature")
	}
	var document nitroDocument
	if err = mode.Unmarshal(payload, &document); err != nil {
		return nitroDocument{}, ErrInvalidTransaction("invalid Nitro attestation document")
	}
	if err = validateNitroDocumentBounds(document); err != nil {
		return nitroDocument{}, ErrInvalidTransaction(err.Error())
	}
	if !bytes.Equal(document.Nonce, message.Nonce) || !bytes.Equal(document.PublicKey, message.PublicKey) ||
		!bytes.Equal(document.UserData, message.UserData) {
		return nitroDocument{}, ErrUnauthorized("Nitro attestation binding mismatch")
	}
	blockMillis := timeMicros / 1_000
	if document.TimestampMS > blockMillis+nitroMaxFutureMillis {
		return nitroDocument{}, ErrUnauthorized("Nitro attestation timestamp is in the future")
	}
	if document.TimestampMS > math.MaxUint64-nitroMaxAgeMillis || document.TimestampMS+nitroMaxAgeMillis < blockMillis {
		return nitroDocument{}, ErrUnauthorized("Nitro attestation is stale")
	}
	leaf, err := x509.ParseCertificate(document.Certificate)
	if err != nil || !bytes.Equal(leaf.Raw, document.Certificate) {
		return nitroDocument{}, ErrCrypto("invalid Nitro attestation certificate")
	}
	intermediates := x509.NewCertPool()
	for _, raw := range document.CABundle {
		certificate, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil || !bytes.Equal(certificate.Raw, raw) {
			return nitroDocument{}, ErrCrypto("invalid Nitro attestation CA certificate")
		}
		intermediates.AddCert(certificate)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	attestedAt := time.UnixMilli(int64(document.TimestampMS))
	if _, err = leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: attestedAt,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nitroDocument{}, ErrCrypto("Nitro certificate chain does not reach the governed root")
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve.Params().BitSize != 384 {
		return nitroDocument{}, ErrCrypto("Nitro attestation certificate is not P-384")
	}
	sigStructure, err := cbor.Marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		return nitroDocument{}, ErrCrypto("encode Nitro COSE signature structure")
	}
	digest := sha512.Sum384(sigStructure)
	r := new(big.Int).SetBytes(signature[:48])
	s := new(big.Int).SetBytes(signature[48:])
	if r.Sign() <= 0 || s.Sign() <= 0 || !ecdsa.Verify(publicKey, digest[:], r, s) {
		return nitroDocument{}, ErrCrypto("invalid Nitro COSE signature")
	}
	return document, nil
}

func validateNitroDocumentBounds(document nitroDocument) error {
	if document.ModuleID == "" || len(document.ModuleID) > maxNitroModuleIDSize || document.Digest != "SHA384" ||
		document.TimestampMS == 0 || document.TimestampMS > math.MaxInt64 || len(document.Certificate) == 0 ||
		len(document.Certificate) > maxNitroCertificateSize || len(document.CABundle) == 0 ||
		len(document.CABundle) > maxNitroCABundleEntries || len(document.PublicKey) != 32 ||
		len(document.Nonce) < 16 || len(document.Nonce) > 64 || len(document.UserData) > 1024 ||
		len(document.PCRs) < 3 || len(document.PCRs) > 32 {
		return errors.New("Nitro attestation fields exceed protocol bounds")
	}
	for _, raw := range document.CABundle {
		if len(raw) == 0 || len(raw) > maxNitroCertificateSize {
			return errors.New("Nitro CA bundle exceeds protocol bounds")
		}
	}
	for index, value := range document.PCRs {
		if index > 31 || len(value) != 48 {
			return errors.New("Nitro attestation contains an invalid PCR bank")
		}
	}
	if !validPCRMeasurements(document.PCRs[0], document.PCRs[1], document.PCRs[2]) {
		return errors.New("Nitro attestation is missing a nonzero PCR tuple")
	}
	return nil
}

func decodeNitroCOSESign1(mode cbor.DecMode, encoded []byte) ([]cbor.RawMessage, error) {
	if len(encoded) == 0 || len(encoded) > maxNitroAttestationSize {
		return nil, errors.New("Nitro attestation exceeds protocol bounds")
	}
	content := encoded
	var tagged cbor.RawTag
	if err := mode.Unmarshal(encoded, &tagged); err == nil {
		if tagged.Number != 18 {
			return nil, errors.New("Nitro attestation has an unexpected CBOR tag")
		}
		content = tagged.Content
	}
	var sign1 []cbor.RawMessage
	if err := mode.Unmarshal(content, &sign1); err != nil || len(sign1) != 4 {
		return nil, errors.New("invalid Nitro COSE_Sign1 envelope")
	}
	return sign1, nil
}
