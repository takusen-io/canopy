package contract

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"

	"google.golang.org/protobuf/proto"
)

const (
	maxCompressedExecutionBatch = 3 << 10
	maxExpandedExecutionBatch   = 64 << 10
	maxExecutionExpansionRatio  = 16
)

// checkCompressedExecutionEnvelope is intentionally allocation-free. CheckTx
// uses it only to discover the outer, authenticated servicer; decompression is
// deferred until DeliverTx, after core has verified that servicer's signature.
func checkCompressedExecutionEnvelope(compressed []byte) *PluginError {
	if len(compressed) < 18 || len(compressed) > maxCompressedExecutionBatch {
		return ErrInvalidTransaction("compressed execution batch is invalid")
	}
	expanded := uint64(binary.LittleEndian.Uint32(compressed[len(compressed)-4:]))
	if expanded == 0 || expanded > maxExpandedExecutionBatch || expanded > uint64(len(compressed))*maxExecutionExpansionRatio {
		return ErrInvalidTransaction("compressed execution batch exceeds its expansion budget")
	}
	return nil
}

// expandExecutionBatch restores the signed receipt messages from their
// transport encoding. Compression changes neither receipt bytes nor enclave
// signatures; it only removes repeated text while the cohort is propagated.
func expandExecutionBatch(message *MessageSubmitExecutions) *PluginError {
	if len(message.CompressedExecutions) == 0 {
		return nil
	}
	if len(message.Executions) != 0 {
		return ErrInvalidTransaction("compressed execution batch is invalid")
	}
	if err := checkCompressedExecutionEnvelope(message.CompressedExecutions); err != nil {
		return err
	}
	reader, err := gzip.NewReader(bytes.NewReader(message.CompressedExecutions))
	if err != nil {
		return ErrInvalidTransaction("compressed execution batch is invalid")
	}
	expanded, readErr := io.ReadAll(io.LimitReader(reader, maxExpandedExecutionBatch+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || len(expanded) > maxExpandedExecutionBatch {
		return ErrInvalidTransaction("compressed execution batch is invalid")
	}
	payload := new(MessageSubmitExecutions)
	if err = proto.Unmarshal(expanded, payload); err != nil || len(payload.Executions) == 0 ||
		len(payload.ServicerAddress) != 0 || len(payload.PublicKey) != 0 || len(payload.CompressedExecutions) != 0 {
		return ErrInvalidTransaction("compressed execution batch is invalid")
	}
	message.Executions = payload.Executions
	return nil
}
