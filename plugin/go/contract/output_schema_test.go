package contract

import (
	"encoding/hex"
	"testing"
)

func TestRequestOutputSchemaHashMatchesSolidityABI(t *testing.T) {
	boolean, _ := hex.DecodeString("dfe58d84d79c0cbbb7049c2ae941fda618361becdde035bdcf8dcc92ce5d21a1")
	message := &MessageObserveAuthorization{OutputType: "boolean", OutputMinimum: 0, OutputMaximum: 1, SchemaHash: boolean}
	if !validRequestOutputSchema(message) {
		t.Fatal("canonical boolean schema hash was rejected")
	}
	choice, _ := hex.DecodeString("a042434ed207bfb427f80bcf32a853e593e20f1441d3fb3d45043871eb00b807")
	message = &MessageObserveAuthorization{OutputType: "choice", OutputMinimum: 'A', OutputMaximum: 'B', OutputChoices: []string{"Alice", "Bob"}, SchemaHash: choice}
	if !validRequestOutputSchema(message) {
		t.Fatalf("canonical choice schema hash was rejected: choices %x schema %x", legacyKeccak256(abiEncodeStrings(message.OutputChoices)), requestOutputSchemaHash(message))
	}
	message.OutputChoices[1] = "Carol"
	if validRequestOutputSchema(message) {
		t.Fatal("changed choice meaning retained the old schema commitment")
	}
}
