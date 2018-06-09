package vvalidator

import (
	"testing"
	"fmt"
	"reflect"
)

func TestIs(t *testing.T) {
	ipv4 := IsIPv4("8.8.8.8")
	equal(t, true, ipv4)
	ipv6 := IsIPv6("2001:db8::68")
	equal(t, true, ipv6)
}

func TestValidate(t *testing.T) {
	defer func() {
		r := recover()
		if err, ok := r.(*Error); ok {
			fmt.Println(err.Message)
		}
	}()

	params := map[string]string{
		"uid":      "123",
		"nickname": "fengmoti",
		"height":   "1.5",
	}

	uid1 := ValidateInt(params, "uid", 0, 200, 10)
	equal(t, 123, uid1)
	uid2 := ValidateInt(params, "uids", 0, 200, 10)
	equal(t, 10, uid2)
	uid3 := ValidateInt(params, "uids", 0, 10, 10)
	equal(t, 10, uid3)
	uid4 := ValidateInt(params, "uid", 0, 10)
	fmt.Println(uid4)
	str := ValidateString(params, "nickname", 0, 20, "default")
	equal(t, "fengmoti", str)
}

// Expected to be equal.
func equal(t *testing.T, expected, actual interface{}) {
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Expected %v (type %v) - Got %v (type %v)", expected, reflect.TypeOf(expected), actual, reflect.TypeOf(actual))
	}
}
