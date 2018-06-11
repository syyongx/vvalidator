package vvalidator

import (
	"strconv"
	"strings"
	"unicode/utf8"
	"errors"
)

// Validate 32 bit integer
func ValidateInt(data interface{}, key string, min, max int, def ... int) (int, error) {
	var defVal interface{}
	ldef := len(def)
	if ldef > 0 {
		defVal = def[0]
	}
	val, err := checkExist(data, key, defVal)
	if err != nil {
		return 0, err
	}

	switch val.(type) {
	case int:
		return val.(int), nil
	case string:
		value := val.(string)
		if !IsInt(value) {
			if ldef == 0 {
				return 0, errors.New(key + " must be an integer")
			}
			return def[0], nil
		}

		v, err := strconv.Atoi(value)
		if err != nil {
			if ldef == 0 {
				return 0, errors.New(key + " must be an integer")
			}
			return def[0], nil
		}
		if min != -1 && v < min {
			if ldef == 0 {
				return 0, errors.New(key + " is too small (minimum is " + strconv.Itoa(min) + ")")
			}
			return def[0], nil
		}
		if max != -1 && v > max {
			if ldef == 0 {
				return 0, errors.New(key + " is too big (maximum is " + strconv.Itoa(max) + ")")
			}
			return def[0], nil
		}
		return v, nil
	default:
		return 0, errors.New("type invalid, must be string or int")
	}
}

// Validate 32 bit integer with custom error info.
func ValidateIntp(data interface{}, key string, min, max int, code int, note string, def ... int) int {
	val, err := ValidateInt(data, key, min, max, def...)
	if err != nil {
		panic(NewError(err.Error(), code, note))
	}
	return val
}

// Validate 64 bit integer.
func ValidateInt64(data interface{}, key string, min, max int64, def ... int64) (int64, error) {
	var defVal interface{}
	ldef := len(def)
	if ldef > 0 {
		defVal = def[0]
	}
	val, err := checkExist(data, key, defVal)
	if err != nil {
		return 0, err
	}

	switch val.(type) {
	case int64:
		return val.(int64), nil
	case string:
		value := val.(string)
		if !IsInt(value) {
			if ldef == 0 {
				return 0, errors.New(key + " must be a valid interger")
			}
			return def[0], nil
		}

		v, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			if ldef == 0 {
				return 0, errors.New(key + " must be a valid interger")
			}
			return def[0], nil
		}
		if min != -1 && v < min {
			if ldef == 0 {
				return 0, errors.New(key + " is too small (minimum is " + strconv.FormatInt(min, 10) + ")")
			}
			return def[0], nil
		}
		if max != -1 && v > max {
			if ldef == 0 {
				return 0, errors.New(key + " is too big (maximum is " + strconv.FormatInt(max, 10) + ")")
			}
			return def[0], nil
		}
		return v, nil
	default:
		return 0, errors.New("type invalid, must be string or int64")
	}
}

// Validate 64 bit integer with custom error info.
func ValidateInt64p(data interface{}, key string, min, max int64, code int, note string, def ... int64) int64 {
	val, err := ValidateInt64(data, key, min, max, def...)
	if err != nil {
		panic(NewError(err.Error(), code, note))
	}
	return val
}

//  Validate 64 bit float.
func ValidateFloat(data interface{}, key string, min, max float64, def ... float64) (float64, error) {
	var defVal interface{}
	ldef := len(def)
	if ldef > 0 {
		defVal = def[0]
	}
	val, err := checkExist(data, key, defVal)
	if err != nil {
		return 0, err
	}

	switch val.(type) {
	case float64:
		return val.(float64), nil
	case string:
		value := val.(string)
		if !IsFloat(value) {
			if ldef == 0 {
				return 0, errors.New(key + " must be a valid float64")
			}
			return def[0], nil
		}

		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			if ldef == 0 {
				return 0, errors.New(key + " must be a valid float64")
			}
			return def[0], nil
		}
		if min != -1 && v < min {
			if ldef == 0 {
				return 0, errors.New(key + " is too small (minimum is " + strconv.FormatFloat(min, 'f', -1, 64) + ")")
			}
			return def[0], nil
		}
		if max != -1 && v > max {
			if ldef == 0 {
				return 0, errors.New(key + " is too big (maximum is " + strconv.FormatFloat(max, 'f', -1, 64) + ")")
			}
			return def[0], nil
		}
		return v, nil
	default:
		return 0, errors.New("type invalid, must be string or float64")
	}
}

//  Validate 64 bit float with custom error info.
func ValidateFloatp(data interface{}, key string, min, max float64, code int, note string, def ... float64) float64 {
	val, err := ValidateFloat(data, key, min, max, def...)
	if err != nil {
		panic(NewError(err.Error(), code, note))
	}
	return val
}

// Validate string.
func ValidateString(data interface{}, key string, min, max int, def ... string) (string, error) {
	var defVal interface{}
	if len(def) != 0 {
		defVal = def[0]
	}
	val, err := checkExist(data, key, defVal)
	if err != nil {
		return "", err
	}

	length := utf8.RuneCountInString(val.(string))
	if len(def) > 0 && length == 0 {
		return def[0], nil
	}
	if min != -1 && length < min {
		return "", errors.New(key + " is too short (minimum is " + strconv.Itoa(min) + " characters)")
	}
	if max != -1 && length > max {
		return "", errors.New(key + " is too long (maximum is " + strconv.Itoa(max) + " characters)")
	}
	return val.(string), nil
}

// Validate string with custom error info.
func ValidateStringp(data interface{}, key string, min, max int, code int, note string, def ... string) string {
	val, err := ValidateString(data, key, min, max, def...)
	if err != nil {
		panic(NewError(err.Error(), code, note))
	}
	return val
}

// Validate enum int.
func ValidateEnumInt(data interface{}, key string, validValues []int, def ... int) (int, error) {
	val, err := ValidateInt(data, key, -1, -1, def...)
	if err != nil {
		return 0, nil
	}
	for _, v := range validValues {
		if v == val {
			return val, nil
		}
	}
	return 0, errors.New(key + " is invalid")
}

// Validate enum int with custom error info.
func ValidateEnumIntp(data interface{}, key string, validValues []int, code int, note string, def ... int) int {
	val, err := ValidateInt(data, key, -1, -1, def...)
	if err != nil {
		panic(NewError(err.Error(), code, note))
	}
	return val
}

// Validate enum int64
func ValidateEnumInt64(data interface{}, key string, validValues []int64, def ... int64) (int64, error) {
	val, err := ValidateInt64(data, key, -1, -1, def...)
	if err != nil {
		return 0, nil
	}
	for _, v := range validValues {
		if v == val {
			return val, nil
		}
	}
	return 0, errors.New(key + " is invalid")
}

// Validate enum int64 with panic.
func ValidateEnumInt64p(data interface{}, key string, validValues []int64, code int, note string, def ... int64) int64 {
	val, err := ValidateInt64(data, key, -1, -1, def...)
	if err != nil {
		panic(NewError(err.Error(), code, note))
	}
	return val
}

// Validate string
func ValidateEnumString(data interface{}, key string, validValues []string, def ... string) (string, error) {
	val, err := ValidateString(data, key, -1, -1, def...)
	if err != nil {
		return "", nil
	}
	for _, v := range validValues {
		if v == val {
			return val, nil
		}
	}
	return "", errors.New(key + " is invalid")
}

// Validate enum string with custom error info.
func ValidateEnumStringp(data interface{}, key string, validValues []string, code int, note string, def ... string) string {
	val, err := ValidateEnumString(data, key, validValues, def...)
	if err != nil {
		panic(NewError(err.Error(), code, note))
	}
	return val
}

// Validate slice.
func ValidateSlice(data interface{}, key, sep string, min, max int, def ... string) ([]string, error) {
	var defVal interface{}
	if len(def) != 0 {
		defVal = def[0]
	}
	val, err := checkExist(data, key, defVal)
	if err != nil {
		return nil, err
	}

	vals := strings.Split(val.(string), sep)
	length := len(vals)
	if min != -1 && length < min {
		return nil, errors.New(key + " is too short (minimum is " + strconv.Itoa(min) + " elements)")
	}
	if max != -1 && length > max {
		return nil, errors.New(key + " is too long (maximum is " + strconv.Itoa(max) + " elements)")
	}
	return vals, nil
}

// Validate slice with custom error info.
func ValidateSlicep(data interface{}, key, sep string, min, max int, code int, note string, def ... string) []string {
	val, err := ValidateSlice(data, key, sep, min, max, def...)
	if err != nil {
		panic(NewError(err.Error(), code, note))
	}
	return val
}

// Chekc exist
func checkExist(data interface{}, key string, def interface{}) (interface{}, error) {
	var val string
	switch data.(type) {
	case string:
		val = data.(string)
	case map[string]string:
		if value, ok := data.(map[string]string)[key]; ok {
			val = value
		} else {
			if def == nil {
				return nil, errors.New(key + " is required")
			}
			return def, nil
		}
	default:
		return nil, errors.New("data type invalid, must be string or map[string]string")
	}

	if val == "" {
		if def == nil {
			return nil, errors.New(key + " can't be empty")
		} else {
			return def, nil
		}
	}

	return val, nil
}
