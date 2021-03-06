package main

import (
	"reflect"
	"testing"
)

// TODO: Write required setup for a local resolver with a variety of domains and test cases
func TestCheckWildcard(t *testing.T) {
	// A simple test domain -- please don't abuse it
	ips := checkWildcard("glugger.ss23.geek.nz")
	expected := []string{"127.0.0.23"}
	if reflect.DeepEqual(ips, expected) == false {
		t.Error(
			"Wildcard detection returned an unexpected result.",
			"Expected: ", expected,
			" - Got: ", ips,
		)
	}

}

func TestZoneTransfer(t *testing.T) {
	// As before, this should be testing against a domain we control, but this will work for now
	if checkZoneTransfer("zonetransfer.me") == false {
		t.Error("Zone transfer attempt on zonetransfer.me failed")
	}
}
