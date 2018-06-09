package vvalidator

import (
	"testing"
)

func TestIs(t *testing.T) {
	ipv4 := IsIPv4("8.8.8.8")
	equal(t, true, ipv4)
	ipv6 := IsIPv6("2001:db8::68")
	equal(t, true, ipv6)
}
