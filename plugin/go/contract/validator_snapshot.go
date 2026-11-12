package contract

import (
	"bytes"
	"encoding/binary"
	"io"
	"sort"

	"google.golang.org/protobuf/proto"
)

const (
	activeValidatorSetEncodingVersion byte = 1
	// The EVM verifier hard-caps 64. Consensus stays below it so queueing and activation
	// retain gas headroom under the maximum supported committee.
	maxValidatorSetSize = 60
)

func decodeActiveValidatorSet(encoded []byte, chainID uint64) (map[string]proto.Message, *PluginError) {
	reader := bytes.NewReader(encoded)
	version, err := reader.ReadByte()
	if err != nil || version != activeValidatorSetEncodingVersion {
		return nil, ErrState("invalid active validator set encoding")
	}
	var encodedChainID uint64
	var count uint32
	if binary.Read(reader, binary.BigEndian, &encodedChainID) != nil || encodedChainID != chainID ||
		binary.Read(reader, binary.BigEndian, &count) != nil || count == 0 || count > maxValidatorSetSize {
		return nil, ErrState("invalid active validator set header")
	}
	records := make(map[string]proto.Message, count)
	for range count {
		address := make([]byte, addressSize)
		var publicKeyLength uint16
		var power uint64
		var netAddressLength uint16
		if _, err = io.ReadFull(reader, address); err != nil || binary.Read(reader, binary.BigEndian, &publicKeyLength) != nil || publicKeyLength == 0 {
			return nil, ErrState("truncated active validator set member")
		}
		publicKey := make([]byte, publicKeyLength)
		if _, err = io.ReadFull(reader, publicKey); err != nil || binary.Read(reader, binary.BigEndian, &power) != nil || power == 0 ||
			binary.Read(reader, binary.BigEndian, &netAddressLength) != nil {
			return nil, ErrState("invalid active validator set member")
		}
		netAddress := make([]byte, netAddressLength)
		if _, err = io.ReadFull(reader, netAddress); err != nil {
			return nil, ErrState("truncated active validator network address")
		}
		key := string(KeyForEpochValidator(0, address))
		if _, duplicate := records[key]; duplicate {
			return nil, ErrState("duplicate active validator address")
		}
		records[key] = &Validator{
			Address: address, PublicKey: publicKey, NetAddress: string(netAddress),
			StakedAmount: power, Committees: []uint64{chainID},
		}
	}
	if reader.Len() != 0 {
		return nil, ErrState("active validator set has trailing data")
	}
	return records, nil
}

func (c *Contract) reconcileEpochValidatorSnapshot(epoch uint64, encoded []byte) (map[string]proto.Message, [][]byte, *PluginError) {
	decoded, err := decodeActiveValidatorSet(encoded, c.Config.ChainId)
	if err != nil {
		return nil, nil, err
	}
	desired := make(map[string]proto.Message, len(decoded))
	for _, message := range decoded {
		validator := message.(*Validator)
		desired[string(KeyForEpochValidator(epoch, validator.Address))] = validator
	}
	existing, readErr := c.rangeRead(EpochValidatorPrefix(epoch))
	if readErr != nil {
		return nil, nil, readErr
	}
	deletes := make([][]byte, 0)
	for _, entry := range existing {
		expected, found := desired[string(entry.Key)]
		if !found {
			deletes = append(deletes, append([]byte(nil), entry.Key...))
			continue
		}
		actual := new(Validator)
		if unmarshalErr := Unmarshal(entry.Value, actual); unmarshalErr != nil {
			return nil, nil, unmarshalErr
		}
		if proto.Equal(actual, expected) {
			delete(desired, string(entry.Key))
		}
	}
	sort.Slice(deletes, func(i, j int) bool { return bytes.Compare(deletes[i], deletes[j]) < 0 })
	return desired, deletes, nil
}
