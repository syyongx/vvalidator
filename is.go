package vvalidator

import (
	"regexp"
	"strings"
	"net"
)

var (
	PatternNumeric        = `^[0-9]+$`
	PatternInt            = `^(?:[-+]?(?:0|[1-9][0-9]*))$`
	PatternFloat          = `^(?:[-+]?(?:[0-9]+))?(?:\\.[0-9]*)?(?:[eE][\\+\\-]?(?:[0-9]+))?$`
	PatternHexadecimal    = `^[0-9a-fA-F]+$`
	PatternAlpha          = `^[a-zA-Z]+$`
	PatternAlphanumeric   = `^[a-zA-Z0-9]+$`
	PatternLatitude       = `^[-+]?([1-8]?\\d(\\.\\d+)?|90(\\.0+)?)$`
	PatternLongitude      = `^[-+]?(180(\\.0+)?|((1[0-7]\\d)|([1-9]?\\d))(\\.\\d+)?)$`
	PatternBase64         = `^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`
	PatternLowerMD5       = `^[0-9a-f]{32}$`
	PatternASCII          = `^[\x00-\x7F]+$`
	PatternPrintableASCII = `^[\x20-\x7E]+$`
	PatternIP             = `(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`
	PatternURLSchema      = `((ftp|tcp|udp|wss?|https?):\/\/)`
	PatternURLUsername    = `(\S+(:\S*)?@)`
	PatternURLPath        = `((\/|\?|#)[^\s]*)`
	PatternURLPort        = `(:(\d{1,5}))`
	PatternURLIP          = `([1-9]\d?|1\d\d|2[01]\d|22[0-3])(\.(1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.([0-9]\d?|1\d\d|2[0-4]\d|25[0-4]))`
	PatternURLSubdomain   = `((www\.)|([a-zA-Z0-9]([-\.][-\._a-zA-Z0-9]+)*))`
	PatternURL            = `^` + PatternURLSchema + `?` + PatternURLUsername + `?` + `((` + PatternURLIP + `|(\[` + PatternIP + `\])|(([a-zA-Z0-9]([a-zA-Z0-9-_]+)?[a-zA-Z0-9]([-\.][a-zA-Z0-9]+)*)|(` + PatternURLSubdomain + `?))?(([a-zA-Z\x{00a1}-\x{ffff}0-9]+-?-?)*[a-zA-Z\x{00a1}-\x{ffff}0-9]+)(?:\.([a-zA-Z\x{00a1}-\x{ffff}]{1,}))?))\.?` + PatternURLPort + `?` + PatternURLPath + `?$`
	PatternEmail          = "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
	PatternWinPath        = `^[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*$`
	PatternUnixPath       = `^(/[^/\x00]*)+/?$`
	PatternSemver         = `^v?(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)(-(0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(\\.(0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?(\\+[0-9a-zA-Z-]+(\\.[0-9a-zA-Z-]+)*)?$`
	PatternFullWidth      = `[^\u0020-\u007E\uFF61-\uFF9F\uFFA0-\uFFDC\uFFE8-\uFFEE0-9a-zA-Z]`
	PatternHalfWidth      = `[\u0020-\u007E\uFF61-\uFF9F\uFFA0-\uFFDC\uFFE8-\uFFEE0-9a-zA-Z]`
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

// IsAlpha checks if the string contains only letters (a-zA-Z).
func IsAlpha(str string) bool {
	return regexp.MustCompile(PatternAlpha).MatchString(str)
}

// IsAlphanumeric checks if the string contains only letters(a-zA-Z) and numbers.
func IsAlphanumeric(str string) bool {
	return regexp.MustCompile(PatternAlphanumeric).MatchString(str)
}

// IsIP checks if the string is valid IP.
func IsIP(str string) bool {
	return net.ParseIP(str) != nil
}

// IsIPv4 checks if the string is valid IPv4.
func IsIPv4(str string) bool {
	ip := net.ParseIP(str)
	if ip == nil {
		return false
	}
	return strings.Contains(str, ".")
}

// IsIPv6 checks if the string is valid IPv6.
func IsIPv6(str string) bool {
	ip := net.ParseIP(str)
	if ip == nil {
		return false
	}
	return strings.Contains(str, ":")
}

// IsLatitude checks if the string is valid latitude.
func IsLatitude(str string) bool {
	return regexp.MustCompile(PatternLatitude).MatchString(str)
}

// IsLongitude checks if the string is valid longitude.
func IsLongitude(str string) bool {
	return regexp.MustCompile(PatternLongitude).MatchString(str)
}

// IsBase64 checks if the string is base64 encoded.
func IsBase64(str string) bool {
	return regexp.MustCompile(PatternBase64).MatchString(str)
}

// IsURL checks if the string is URL.
func IsURL(str string) bool {
	return regexp.MustCompile(PatternURL).MatchString(str)
}

// IsASCII checks if the string is ASCII.
func IsASCII(str string) bool {
	return regexp.MustCompile(PatternASCII).MatchString(str)
}

// IsPrintableASCII checks if the string is printable ASCII.
func IsPrintableASCII(str string) bool {
	return regexp.MustCompile(PatternPrintableASCII).MatchString(str)
}

// IsEmail checks if the string is email.
func IsEmail(str string) bool {
	return regexp.MustCompile(PatternEmail).MatchString(str)
}

// IsWinPath checks if the string is windows path.
func IsWinPath(str string) bool {
	return regexp.MustCompile(PatternWinPath).MatchString(str)
}

// IsUnixPath checks if the string is unix path.
func IsUnixPath(str string) bool {
	return regexp.MustCompile(PatternUnixPath).MatchString(str)
}

// IsSemver checks if the string is valid Semantic Version.
func IsSemver(str string) bool {
	return regexp.MustCompile(PatternSemver).MatchString(str)
}

// IsFullWidth checks if the string is contains any full-width chars.
func IsFullWidth(str string) bool {
	return regexp.MustCompile(PatternFullWidth).MatchString(str)
}

// IsHalfWidth checks if the string is contains any half-width chars.
func IsHalfWidth(str string) bool {
	return regexp.MustCompile(PatternHalfWidth).MatchString(str)
}

// IsHash checks if a string is a hash of type algorithm.
// Algorithm is one of
// [ 'md4', 'md5', 'sha1', 'sha256', 'sha384', 'sha512',
// 'ripemd128', 'ripemd160', 'tiger128', 'tiger160', 'tiger192',
// 'crc32', 'crc32b']
func IsHash(str, algorithm string) bool {
	len := "0"
	algo := strings.ToLower(algorithm)

	if algo == "crc32" || algo == "crc32b" {
		len = "8"
	} else if algo == "md5" || algo == "md4" || algo == "ripemd128" || algo == "tiger128" {
		len = "32"
	} else if algo == "sha1" || algo == "ripemd160" || algo == "tiger160" {
		len = "40"
	} else if algo == "tiger192" {
		len = "48"
	} else if algo == "sha256" {
		len = "64"
	} else if algo == "sha384" {
		len = "96"
	} else if algo == "sha512" {
		len = "128"
	} else {
		return false
	}

	return regexp.MustCompile("^[a-f0-9]{" + len + "}$").MatchString(str)
}
