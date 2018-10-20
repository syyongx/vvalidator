package vvalidator

import (
	"fmt"
	"reflect"
	"testing"
)

func TestValidate(t *testing.T) {
	defer func() {
		r := recover()
		if err, ok := r.(Error); ok {
			fmt.Println(err.Message)
		}
	}()

	params := map[string]string{
		"uid":      "123",
		"nickname": "fengmoti",
		"height":   "1.5",
	}

	uid1, err1 := ValidateInt(params, "uid", 0, 200, 10)
	equal(t, 123, uid1)
	equal(t, nil, err1)
	uid2, err2 := ValidateInt(params, "uids", 0, 200, 10)
	equal(t, 10, uid2)
	equal(t, nil, err2)
	uid3, err3 := ValidateInt(params, "uids", 0, 10, 10)
	equal(t, 10, uid3)
	equal(t, nil, err3)
	uid4, err4 := ValidateInt(params, "uid", 0, 10)
	fmt.Println(uid4)
	equal(t, "uid is too big (maximum is 10)", err4.Error())
	str, err5 := ValidateString(params, "nickname", 0, 20, "default")
	equal(t, "fengmoti", str)
	equal(t, "uid is too big (maximum is 10)", err5.Error())
}

// Expected to be equal.
func equal(t *testing.T, expected, actual interface{}) {
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Expected %v (type %v) - Got %v (type %v)", expected, reflect.TypeOf(expected), actual, reflect.TypeOf(actual))
	}
}
