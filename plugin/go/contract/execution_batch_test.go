package contract

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestCompressedExecutionSignerDiscoveryNeverDecompresses(t *testing.T) {
	// This has a plausible gzip header/footer and bounded ISIZE but an invalid
	// deflate stream. CheckTx must still discover the authenticated outer signer
	// without parsing it; DeliverTx is where decompression must fail.
	compressed := append([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0}, bytes.Repeat([]byte{0x7f}, 8)...)
	compressed = append(compressed, make([]byte, 8)...)
	binary.LittleEndian.PutUint32(compressed[len(compressed)-4:], 32)
	message := &MessageSubmitExecutions{
		ServicerAddress:      bytes.Repeat([]byte{1}, addressSize),
		PublicKey:            bytes.Repeat([]byte{2}, ed25519.PublicKeySize),
		CompressedExecutions: compressed,
	}
	if _, err := checkSubmitExecutions(message); err != nil {
		t.Fatalf("signer discovery parsed unauthenticated gzip: %v", err)
	}
	if err := expandExecutionBatch(message); err == nil {
		t.Fatal("delivery accepted an invalid gzip stream")
	}
}

func TestCompressedExecutionRejectsExpansionBomb(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write(make([]byte, maxExpandedExecutionBatch))
	_ = writer.Close()
	if err := checkCompressedExecutionEnvelope(compressed.Bytes()); err == nil {
		t.Fatal("high-ratio gzip bomb passed the pre-authentication envelope check")
	}
}

func TestCompressedExecutionExpandsWithinReceiptBudget(t *testing.T) {
	receipt := make([]byte, 1024)
	signature := make([]byte, ed25519.SignatureSize)
	_, _ = rand.Read(receipt)
	_, _ = rand.Read(signature)
	payload, err := proto.Marshal(&MessageSubmitExecutions{Executions: []*MessageSubmitExecution{{ReceiptJson: receipt, Signature: signature}}})
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write(payload)
	_ = writer.Close()
	message := &MessageSubmitExecutions{
		ServicerAddress:      bytes.Repeat([]byte{1}, addressSize),
		PublicKey:            bytes.Repeat([]byte{2}, ed25519.PublicKeySize),
		CompressedExecutions: compressed.Bytes(),
	}
	if _, checkErr := checkSubmitExecutions(message); checkErr != nil {
		t.Fatal(checkErr)
	}
	if expandErr := expandExecutionBatch(message); expandErr != nil {
		t.Fatal(expandErr)
	}
	if validateErr := validateExecutionBatchItems(message); validateErr != nil {
		t.Fatal(validateErr)
	}
}

func BenchmarkCompressedExecutionProposalRecheck(b *testing.B) {
	compressed := append([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0}, bytes.Repeat([]byte{0x7f}, 8)...)
	compressed = append(compressed, make([]byte, 8)...)
	binary.LittleEndian.PutUint32(compressed[len(compressed)-4:], 32)
	for b.Loop() {
		message := &MessageSubmitExecutions{
			ServicerAddress:      bytes.Repeat([]byte{1}, addressSize),
			PublicKey:            bytes.Repeat([]byte{2}, ed25519.PublicKeySize),
			CompressedExecutions: compressed,
		}
		if _, err := checkSubmitExecutions(message); err != nil {
			b.Fatal(err)
		}
	}
}
