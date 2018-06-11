package vvalidator

import (
	"testing"
)

func TestHas(t *testing.T) {
	lc := HasLowerCase("aA")
	equal(t, true, lc)
	uc := HasUpperCase("aA")
	equal(t, true, uc)
}
