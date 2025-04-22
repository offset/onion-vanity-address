package require

import (
	"reflect"
	"testing"
)

// True requires that the value is true, failing the test if not
func True(t *testing.T, value bool) {
	if !value {
		t.Helper()
		t.Fatal("Should be true")
	}
}

// False requires that the value is false, failing the test if not
func False(t *testing.T, value bool) {
	if value {
		t.Helper()
		t.Fatal("Should be false")
	}
}

// Equal requires that expected and actual are equal using reflect.DeepEqual
func Equal(t *testing.T, expected, actual any) {
	if !reflect.DeepEqual(expected, actual) {
		t.Helper()
		t.Fatalf("Not equal:\nexpected: %v\n  actual: %v", expected, actual)
	}
}

// NoError requires that the error is nil, failing the test if not
func NoError(t *testing.T, err error) {
	if err != nil {
		t.Helper()
		t.Fatalf("Received unexpected error: %+v", err)
	}
}
