package assert

import (
	"reflect"
	"testing"
)

// True asserts that the value is true
func True(t *testing.T, value bool) {
	if !value {
		t.Helper()
		t.Error("Should be true")
	}
}

// False asserts that the value is false
func False(t *testing.T, value bool) {
	if value {
		t.Helper()
		t.Error("Should be false")
	}
}

// Equal asserts that expected and actual are equal using reflect.DeepEqual
func Equal(t *testing.T, expected, actual any) {
	if !reflect.DeepEqual(expected, actual) {
		t.Helper()
		t.Errorf("Not equal:\nexpected: %v\n  actual: %v", expected, actual)
	}
}

// NoError asserts that the error is nil
func NoError(t *testing.T, err error) {
	if err != nil {
		t.Helper()
		t.Errorf("Received unexpected error: %+v", err)
	}
}
