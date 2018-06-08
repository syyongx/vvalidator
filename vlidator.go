package vvalidator

import (
	"regexp"
	"strconv"
	"strings"
	"net"
	"unicode/utf8"
)

var (
	PatternNumeric      = `^[0-9]+$`
	PatternInt          = `^(?:[-+]?(?:0|[1-9][0-9]*))$`
	PatternFloat        = `^(?:[-+]?(?:[0-9]+))?(?:\\.[0-9]*)?(?:[eE][\\+\\-]?(?:[0-9]+))?$`
	PatternHexadecimal  = `^[0-9a-fA-F]+$`
	PatternAlpha        = `^[a-zA-Z]+$`
	PatternAlphanumeric = `^[a-zA-Z0-9]+$`
	PatternLatitude     = `^[-+]?([1-8]?\\d(\\.\\d+)?|90(\\.0+)?)$`
	PatternLongitude    = `^[-+]?(180(\\.0+)?|((1[0-7]\\d)|([1-9]?\\d))(\\.\\d+)?)$`
	PatternBase64       = `^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`
	PatternLowerMD5     = `^[0-9a-f]{32}$`
	PatternASCII        = `^[\x00-\x7F]+$`
	PatternIP           = `(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`
	PatternURLSchema    = `((ftp|tcp|udp|wss?|https?):\/\/)`
	PatternURLUsername  = `(\S+(:\S*)?@)`
	PatternURLPath      = `((\/|\?|#)[^\s]*)`
	PatternURLPort      = `(:(\d{1,5}))`
	PatternURLIP        = `([1-9]\d?|1\d\d|2[01]\d|22[0-3])(\.(1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.([0-9]\d?|1\d\d|2[0-4]\d|25[0-4]))`
	PatternURLSubdomain = `((www\.)|([a-zA-Z0-9]([-\.][-\._a-zA-Z0-9]+)*))`
	PatternURL          = `^` + PatternURLSchema + `?` + PatternURLUsername + `?` + `((` + PatternURLIP + `|(\[` + PatternIP + `\])|(([a-zA-Z0-9]([a-zA-Z0-9-_]+)?[a-zA-Z0-9]([-\.][a-zA-Z0-9]+)*)|(` + PatternURLSubdomain + `?))?(([a-zA-Z\x{00a1}-\x{ffff}0-9]+-?-?)*[a-zA-Z\x{00a1}-\x{ffff}0-9]+)(?:\.([a-zA-Z\x{00a1}-\x{ffff}]{1,}))?))\.?` + PatternURLPort + `?` + PatternURLPath + `?$`
	PatternEmail        = "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

// Check is integer
func IsNumeric(str string) bool {
	return regexp.MustCompile(PatternNumeric).MatchString(str)
}

// Check is integer
func IsInt(str string) bool {
	return regexp.MustCompile(PatternInt).MatchString(str)
}

func IsFloat(str string) bool {
	return regexp.MustCompile(PatternFloat).MatchString(str)
}

// Check if the string is a hexadecimal number.
func IsHexadecimal(str string) bool {
	return regexp.MustCompile(PatternHexadecimal).MatchString(str)
}

func IsAlpha(str string) bool {
	return regexp.MustCompile(PatternAlpha).MatchString(str)
}

func IsAlphanumeric(str string) bool {
	return regexp.MustCompile(PatternAlphanumeric).MatchString(str)
}

func IsIP(str string) bool {
	return net.ParseIP(str) != nil
}

func IsIPv4(str string) bool {
	ip := net.ParseIP(str)
	if ip == nil {
		return false
	}
	return strings.Contains(str, ".")
}

func IsIPv6(str string) bool {
	ip := net.ParseIP(str)
	if ip == nil {
		return false
	}
	return strings.Contains(str, ":")
}

// Check if the string is valid latitude.
func IsLatitude(str string) bool {
	return regexp.MustCompile(PatternLatitude).MatchString(str)
}

// Check if the string is valid longitude.
func IsLongitude(str string) bool {
	return regexp.MustCompile(PatternLongitude).MatchString(str)
}

// Check if the string is MD5 encoded.
func IsMD5(str string) bool {
	str = strings.ToLower(str)
	return regexp.MustCompile(PatternLowerMD5).MatchString(str)
}

// Check if the string is base64 encoded.
func IsBase64(str string) bool {
	return regexp.MustCompile(PatternBase64).MatchString(str)
}

func IsURL(str string) bool {
	return regexp.MustCompile(PatternURL).MatchString(str)
}

func IsASCII(str string) bool {
	return regexp.MustCompile(PatternASCII).MatchString(str)
}

func IsEmail(str string) bool {
	return regexp.MustCompile(PatternEmail).MatchString(str)
}

// Validate 32 bit integer with custom error info.
func ValidateInte(data interface{}, key string, min, max int, code int, note string, def ... int) int {
	var defVal interface{}
	ldef := len(def)
	if ldef > 0 {
		defVal = def[0]
	}
	val := checkExist(data, key, code, note, defVal)
	if value, ok := val.(string); ok {
		if !IsInt(value) {
			if ldef == 0 {
				panic("xxx")
			}
			return def[0]
		}
		v, err := strconv.Atoi(value)
		if err != nil {
			if ldef == 0 {
				panic("xxx")
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
	} else {
		return def[0]
	}
}

// Validate 32 bit integer
func ValidateInt(data interface{}, key string, min, max int, def ... int) int {
	return ValidateInte(data, key, min, max, DefaultCode, "", def...)
}

// Validate 64 bit integer with custom error info.
func ValidateInt64e(data interface{}, key string, min, max int64, code int, note string, def ... int64) int64 {
	var defVal interface{}
	ldef := len(def)
	if ldef > 0 {
		defVal = def[0]
	}
	val := checkExist(data, key, code, note, defVal)
	if value, ok := val.(string); ok {
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
	} else {
		return def[0]
	}
}

// Validate 64 bit integer.
func ValidateInt64(data interface{}, key string, min, max int64, def ... int64) int64 {
	return ValidateInt64e(data, key, min, max, DefaultCode, "", def...)
}

//  Validate 64 bit float with custom error info.
func ValidateFloate(data interface{}, key string, min, max float64, code int, note string, def ... float64) float64 {
	var defVal interface{}
	ldef := len(def)
	if ldef > 0 {
		defVal = def[0]
	}
	val := checkExist(data, key, code, note, defVal)
	if !IsFloat(val.(string)) {
		if ldef == 0 {
			panic(NewError(key+" must be a valid float", code, note))
		}
		return def[0]
	}
	value, err := strconv.ParseFloat(val.(string), 2)
	if err != nil {
		if ldef == 0 {
			panic(NewError(key+" must be a valid interger", code, note))
		}
		return def[0]
	}
	if min != -1 && value < min {
		if ldef == 0 {
			panic(NewError(key+" is too small (minimum is "+strconv.FormatFloat(min, 'f', -1, 64)+")", code, note))
		}
		return def[0]
	}
	if max != -1 && value > max {
		if ldef == 0 {
			panic(NewError(key+" is too big (maximum is "+strconv.FormatFloat(max, 'f', -1, 64)+")", code, note))
		}
		return def[0]
	}

	return value
}

func ValidateFloat(data interface{}, key string, min, max float64, code int, note string, def ... float64) float64 {
	return ValidateFloate(data, key, min, max, DefaultCode, "", def...)
}

// Validate enum int with custom error info.
func ValidateEnumInte(data interface{}, key string, validValues []int, code int, note string, def ... int) int {
	val := ValidateInte(data, key, -1, -1, code, note, def...)
	for _, v := range validValues {
		if v == val {
			return val
		}
	}
	panic(NewError(key+" is not valid", code, note))
}

// Validate enum int.
func ValidateEnumInt(data interface{}, key string, validValues []int, code int, note string, def ... int) int {
	return ValidateEnumInte(data, key, validValues, DefaultCode, "", def...)
}

// Validate enum int64
func ValidateEnumInt64e(data interface{}, key string, validValues []int64, code int, note string, def ... int64) int64 {
	val := ValidateInt64e(data, key, -1, -1, code, note, def...)
	for _, v := range validValues {
		if v == val {
			return val
		}
	}
	panic(NewError(key+" is not valid", code, note))
}

// Validate enum int64
func ValidateEnumInt64(data interface{}, key string, validValues []int64, code int, note string, def ... int64) int64 {
	return ValidateEnumInt64e(data, key, validValues, DefaultCode, "", def...)
}

// Validate enum string with custom error info.
func ValidateEnumStringe(data interface{}, key string, validValues []string, code int, note string, def ... string) string {
	val := ValidateStringe(data, key, -1, -1, code, note, def...)
	for _, v := range validValues {
		if v == val {
			return val
		}
	}
	panic(key + " is not valid")
}

// Validate string
func ValidateEnumString(data interface{}, key string, validValues []string, def ... string) string {
	return ValidateEnumStringe(data, key, validValues, DefaultCode, "", def...)
}

// Validate string with custom error info.
func ValidateStringe(data interface{}, key string, min, max int, code int, note string, def ... string) string {
	var defVal interface{}
	if len(def) != 0 {
		defVal = def[0]
	}
	val := checkExist(data, key, code, note, defVal)

	if value, ok := val.(string); ok {
		length := utf8.RuneCountInString(value)
		if min != -1 && length < min {
			panic(NewError(key+"is too short (minimum is "+strconv.Itoa(min)+" characters)", code, note))
		}
		if max != -1 && length > max {
			panic(NewError(key+"is too long (maximum is "+strconv.Itoa(max)+" characters)", code, note))
		}
		return value
	} else {
		return def[0]
	}
}

// Validate string.
func ValidateString(data interface{}, key string, min, max int, def ... string) string {
	return ValidateStringe(data, key, min, max, DefaultCode, "", def...)
}

// Validate slice with custom error info.
func ValidateSlicee(data interface{}, key, sep string, min, max int, code int, note string, def ... string) []string {
	var defVal interface{}
	if len(def) != 0 {
		defVal = def[0]
	}
	val := checkExist(data, key, code, note, defVal)

	if value, ok := val.(string); ok {
		vals := strings.Split(value, sep)
		length := len(vals)
		if min != -1 && length < min {
			panic(key + "is too short (minimum is " + strconv.Itoa(min) + " elements)")
		}
		if max != -1 && length > max {
			panic(NewError(key+"is too long (maximum is "+strconv.Itoa(max)+" elements)", code, note))
		}
		return vals
	} else {
		panic(NewError("xxx", code, note))
	}
}

// Validate slice.
func ValidateSlice(data interface{}, key, sep string, min, max int, def ... string) []string {
	return ValidateSlicee(data, key, sep, min, max, DefaultCode, "", def...)
}

// Chekc exist
func checkExist(data interface{}, key string, code int, note string, def interface{}) interface{} {
	var val string

	switch data.(type) {
	case string:
		val = data.(string)
	case map[string]string:
		if val, ok := data.(map[string]string)[key]; ok {
			if val == "" {
				if def == nil {
					panic(NewError(key+"is required", code, note))
				} else {
					return def
				}
			}
		} else if def == nil {
			panic(NewError(key+" is required", code, note))
		} else {
			return def
		}
	default:
		panic("data type nonsupport")
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
