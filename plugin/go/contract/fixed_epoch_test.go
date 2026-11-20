package contract

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestUnchangedValidatorEpochsAreExactlyOneHour(t *testing.T) {
	contract, store, proposer, _ := newMemoryContract(t)

	if response := contract.endBlock(epochEndRequestWithWeights(1, 100, proposer, 100, 100)); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := contract.endBlock(epochEndRequestWithWeights(2, 1_299, proposer, 100, 100)); response.Error != nil || response.ValidatorSetEpochPrepare || response.ValidatorSetEpochEnd {
		t.Fatalf("pre-freeze response = %#v", response)
	}
	if response := contract.endBlock(epochEndRequestWithWeights(3, 1_300, proposer, 100, 100)); response.Error != nil || !response.ValidatorSetEpochPrepare || response.ValidatorSetEpochEnd {
		t.Fatalf("freeze response = %#v", response)
	}
	if response := contract.endBlock(epochEndRequestWithWeights(4, 3_699, proposer, 100, 100)); response.Error != nil || response.ValidatorSetEpochEnd {
		t.Fatalf("pre-boundary response = %#v", response)
	}
	if response := contract.endBlock(epochEndRequestWithWeights(5, 3_700, proposer, 100, 100)); response.Error != nil || !response.ValidatorSetEpochEnd {
		t.Fatalf("one-hour boundary response = %#v", response)
	}

	clock := new(EpochClock)
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found {
		t.Fatalf("epoch clock: found=%v err=%v", found, err)
	}
	if clock.CurrentEpoch != 2 || clock.ValidatorSetId != 1 || clock.StartTimestamp != 3_700 || clock.FreezeTimestamp != 4_900 || clock.NominalEndTimestamp != 7_300 {
		t.Fatalf("next fixed epoch = %#v", clock)
	}
	if _, found := store.values[string(KeyForValidatorHandoffManifest())]; found {
		t.Fatal("unchanged roster created a cross-chain handoff manifest")
	}
}

func TestReadyChangedRosterStillEndsAtTheOneHourBoundary(t *testing.T) {
	contract, _, proposer, _ := newMemoryContract(t)

	if response := contract.endBlock(epochEndRequestWithWeights(1, 100, proposer, 100, 100)); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := contract.endBlock(epochEndRequestWithWeights(2, 1_300, proposer, 101, 100)); response.Error != nil || !response.ValidatorSetEpochPrepare {
		t.Fatalf("changed-roster freeze response = %#v", response)
	}
	clock := new(EpochClock)
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found || !clock.ValidatorHandoffPrepared || clock.ValidatorHandoffTimestamp != 3_700 {
		t.Fatalf("prepared handoff = %#v found=%v err=%v", clock, found, err)
	}
	clock.ValidatorHandoffResolvedCount = clock.ValidatorHandoffDomainCount
	if err := contract.write(map[string]proto.Message{string(KeyForEpochClock()): clock}); err != nil {
		t.Fatal(err)
	}
	if response := contract.endBlock(epochEndRequestWithWeights(3, 3_700, proposer, 101, 100)); response.Error != nil || !response.ValidatorSetEpochEnd {
		t.Fatalf("ready one-hour handoff response = %#v", response)
	}
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found || clock.CurrentEpoch != 2 || clock.ValidatorSetId != 2 || clock.StartTimestamp != 3_700 || clock.NominalEndTimestamp != 7_300 {
		t.Fatalf("advanced epoch = %#v found=%v err=%v", clock, found, err)
	}
}
