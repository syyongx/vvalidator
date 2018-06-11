package vvalidator

import (
	"regexp"
)

const (
	PatternLowerCase = ".*[[:lower:]]"
	PatternUpperCase = ".*[[:upper:]]"
)

// HasLowerCase check if the string contains at least 1 lowercase.
func HasLowerCase(str string) bool {
	return regexp.MustCompile(PatternLowerCase).MatchString(str)
}

// HasUpperCase check if the string contians as least 1 uppercase.
func HasUpperCase(str string) bool {
	return regexp.MustCompile(PatternUpperCase).MatchString(str)
}
