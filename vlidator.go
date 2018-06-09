package vvalidator

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// Validate 32 bit integer
func ValidateInt(data interface{}, key string, min, max int, def ... int) int {
	return ValidateInte(data, key, min, max, DefaultCode, "", def...)
}

// Validate 32 bit integer with custom error info.
func ValidateInte(data interface{}, key string, min, max int, code int, note string, def ... int) int {
	var defVal interface{}
	ldef := len(def)
	if ldef > 0 {
		defVal = def[0]
	}
	val := checkExist(data, key, code, note, defVal)

	switch val.(type) {
	case int:
		return val.(int)
	case string:
		value := val.(string)
		if !IsInt(value) {
			if ldef == 0 {
				panic(NewError(key+" must be an integer", code, note))
			}
			return def[0]
		}

		v, err := strconv.Atoi(value)
		if err != nil {
			if ldef == 0 {
				panic(NewError(key+" must be an integer", code, note))
			}
			return def[0]
		}
		if min != -1 && v < min {
			if ldef == 0 {
				panic(NewError(key+" is too small (minimum is "+strconv.Itoa(min)+")", code, note))
			}
			return def[0]
		}
		if max != -1 && v > max {
			if ldef == 0 {
				panic(NewError(key+" is too big (maximum is "+strconv.Itoa(max)+")", code, note))
			}
			return def[0]
		}
		return v
	default:
		panic("type invalid, must be string or int")
	}
}

// Validate 64 bit integer.
func ValidateInt64(data interface{}, key string, min, max int64, def ... int64) int64 {
	return ValidateInt64e(data, key, min, max, DefaultCode, "", def...)
}

// Validate 64 bit integer with custom error info.
func ValidateInt64e(data interface{}, key string, min, max int64, code int, note string, def ... int64) int64 {
	var defVal interface{}
	ldef := len(def)
	if ldef > 0 {
		defVal = def[0]
	}
	val := checkExist(data, key, code, note, defVal)

	switch val.(type) {
	case int64:
		return val.(int64)
	case string:
		value := val.(string)
		if !IsInt(value) {
			if ldef == 0 {
				panic(NewError(key+" must be a valid interger", code, note))
			}
			return def[0]
		}

		v, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			if ldef == 0 {
				panic(NewError(key+" must be a valid interger", code, note))
			}
			return def[0]
		}
		if min != -1 && v < min {
			if ldef == 0 {
				panic(NewError(key+" is too small (minimum is "+strconv.FormatInt(min, 10)+")", code, note))
			}
			return def[0]
		}
		if max != -1 && v > max {
			if ldef == 0 {
				panic(NewError(key+" is too big (maximum is "+strconv.FormatInt(max, 10)+")", code, note))
			}
			return def[0]
		}
		return v
	default:
		panic("type invalid, must be string or int64")
	}
}

//  Validate 64 bit float.
func ValidateFloat(data interface{}, key string, min, max float64, def ... float64) float64 {
	return ValidateFloate(data, key, min, max, DefaultCode, "", def...)
}

//  Validate 64 bit float with custom error info.
func ValidateFloate(data interface{}, key string, min, max float64, code int, note string, def ... float64) float64 {
	var defVal interface{}
	ldef := len(def)
	if ldef > 0 {
		defVal = def[0]
	}
	val := checkExist(data, key, code, note, defVal)
	switch val.(type) {
	case float64:
		return val.(float64)
	case string:
		value := val.(string)
		if !IsFloat(value) {
			if ldef == 0 {
				panic(NewError(key+" must be a valid float", code, note))
			}
			return def[0]
		}

		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			if ldef == 0 {
				panic(NewError(key+" must be a valid interger", code, note))
			}
			return def[0]
		}
		if min != -1 && v < min {
			if ldef == 0 {
				panic(NewError(key+" is too small (minimum is "+strconv.FormatFloat(min, 'f', -1, 64)+")", code, note))
			}
			return def[0]
		}
		if max != -1 && v > max {
			if ldef == 0 {
				panic(NewError(key+" is too big (maximum is "+strconv.FormatFloat(max, 'f', -1, 64)+")", code, note))
			}
			return def[0]
		}
		return v
	default:
		panic("type invalid, must be string or float64")
	}
}

// Validate enum int.
func ValidateEnumInt(data interface{}, key string, validValues []int, def ... int) int {
	return ValidateEnumInte(data, key, validValues, DefaultCode, "", def...)
}

// Validate enum int with custom error info.
func ValidateEnumInte(data interface{}, key string, validValues []int, code int, note string, def ... int) int {
	val := ValidateInte(data, key, -1, -1, code, note, def...)
	for _, v := range validValues {
		if v == val {
			return val
		}
	}
	panic(NewError(key+" is invalid", code, note))
}

// Validate enum int64
func ValidateEnumInt64(data interface{}, key string, validValues []int64, def ... int64) int64 {
	return ValidateEnumInt64e(data, key, validValues, DefaultCode, "", def...)
}

// Validate enum int64
func ValidateEnumInt64e(data interface{}, key string, validValues []int64, code int, note string, def ... int64) int64 {
	val := ValidateInt64e(data, key, -1, -1, code, note, def...)
	for _, v := range validValues {
		if v == val {
			return val
		}
	}
	panic(NewError(key+" is invalid", code, note))
}

// Validate string
func ValidateEnumString(data interface{}, key string, validValues []string, def ... string) string {
	return ValidateEnumStringe(data, key, validValues, DefaultCode, "", def...)
}

// Validate enum string with custom error info.
func ValidateEnumStringe(data interface{}, key string, validValues []string, code int, note string, def ... string) string {
	val := ValidateStringe(data, key, -1, -1, code, note, def...)
	for _, v := range validValues {
		if v == val {
			return val
		}
	}
	panic(NewError(key+" is invalid", code, note))
}

// Validate string with custom error info.
func ValidateStringe(data interface{}, key string, min, max int, code int, note string, def ... string) string {
	var defVal interface{}
	if len(def) != 0 {
		defVal = def[0]
	}
	val := checkExist(data, key, code, note, defVal)

	length := utf8.RuneCountInString(val.(string))
	if len(def) > 0 && length == 0 {
		return def[0]
	}
	if min != -1 && length < min {
		panic(NewError(key+" is too short (minimum is "+strconv.Itoa(min)+" characters)", code, note))
	}
	if max != -1 && length > max {
		panic(NewError(key+" is too long (maximum is "+strconv.Itoa(max)+" characters)", code, note))
	}
	return val.(string)
}

// Validate string.
func ValidateString(data interface{}, key string, min, max int, def ... string) string {
	return ValidateStringe(data, key, min, max, DefaultCode, "", def...)
}

// Validate slice.
func ValidateSlice(data interface{}, key, sep string, min, max int, def ... string) []string {
	return ValidateSlicee(data, key, sep, min, max, DefaultCode, "", def...)
}

// Validate slice with custom error info.
func ValidateSlicee(data interface{}, key, sep string, min, max int, code int, note string, def ... string) []string {
	var defVal interface{}
	if len(def) != 0 {
		defVal = def[0]
	}
	val := checkExist(data, key, code, note, defVal)

	vals := strings.Split(val.(string), sep)
	length := len(vals)
	if min != -1 && length < min {
		panic(NewError(key+" is too short (minimum is "+strconv.Itoa(min)+" elements)", code, note))
	}
	if max != -1 && length > max {
		panic(NewError(key+" is too long (maximum is "+strconv.Itoa(max)+" elements)", code, note))
	}
	return vals
}

// Chekc exist
func checkExist(data interface{}, key string, code int, note string, def interface{}) interface{} {
	var val string
	switch data.(type) {
	case string:
		val = data.(string)
	case map[string]string:
		if value, ok := data.(map[string]string)[key]; ok {
			val = value
		} else {
			if def == nil {
				panic(NewError(key+" is required", code, note))
			}
			return def
		}
	default:
		panic(NewError("data type invalid, must be string or map[string]string", code, note))
	}

	if val == "" {
		if def == nil {
			panic(NewError(key+" can't be empty", code, note))
		} else {
			return def
		}
	}

	return val
}
