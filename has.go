package vvalidator

import (
	"regexp"
)

const (
	PatternHasLowerCase = ".*[[:lower:]]"
	PatternHasUpperCase = ".*[[:upper:]]"
)

// HasLowerCase check if the string contains at least 1 lowercase.
func HasLowerCase(str string) bool {
	return regexp.MustCompile(PatternHasLowerCase).MatchString(str)
}

// HasUpperCase check if the string contians as least 1 uppercase.
func HasUpperCase(str string) bool {
	return regexp.MustCompile(PatternHasUpperCase).MatchString(str)
}
