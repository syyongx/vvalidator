package vvalidator

import (
	"testing"
	"fmt"
)

func TestIs(t *testing.T) {
	param := ""
	str := ValidateString(param, "param", 1, 5, "yyy")
	fmt.Println(str)
	res1 := IsIPv4("111.111.111.255")
	fmt.Println(res1)
	res2 := IsIPv6("2001:db8::68")
	fmt.Println(res2)
}
