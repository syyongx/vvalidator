# vvalidator
Go paramater validator library.

## Download & Install
```shell
go get github.com/syyongx/vvalidator
```

## Apis
### validator
```go
ValidateInt(data interface{}, key string, min, max int, def ... int) (int, error)
ValidateIntp(data interface{}, key string, min, max int, code int, message string, def ... int) int
ValidateInt64(data interface{}, key string, min, max int64, def ... int64) (int64, error)
ValidateInt64p(data interface{}, key string, min, max int64, code int, message string, def ... int64) int64
ValidateFloat(data interface{}, key string, min, max float64, def ... float64) (float64, error)
ValidateFloatp(data interface{}, key string, min, max float64, code int, message string, def ... float64) float64
ValidateString(data interface{}, key string, min, max int, def ... string) (string, error)
ValidateStringp(data interface{}, key string, min, max int, code int, message string, def ... string) string
ValidateStringWithPattern(data interface{}, key, pattern string, def ... string) (string, error)
ValidateStringWithPatternp(data interface{}, key, pattern string, code int, message string, def ... string) string
ValidateEnumInt(data interface{}, key string, validValues []int, def ... int) (int, error)
ValidateEnumIntp(data interface{}, key string, validValues []int, code int, message string, def ... int) int
ValidateEnumInt64(data interface{}, key string, validValues []int64, def ... int64) (int64, error)
ValidateEnumInt64p(data interface{}, key string, validValues []int64, code int, message string, def ... int64) int64
ValidateEnumString(data interface{}, key string, validValues []string, def ... string) (string, error)
ValidateEnumStringp(data interface{}, key string, validValues []string, code int, message string, def ... string) string
ValidateSlice(data interface{}, key, sep string, min, max int, def ... string) ([]string, error)
ValidateSlicep(data interface{}, key, sep string, min, max int, code int, message string, def ... string) []string
```

### is
```go
IsNumeric(str string) bool
IsInt(str string) bool
IsFloat(str string) bool
IsHexadecimal(str string) bool
IsAlpha(str string) bool
IsAlphanumeric(str string) bool
IsIP(str string) bool
IsIPv4(str string) bool
IsIPv6(str string) bool
IsLatitude(str string) bool
IsLongitude(str string) bool
IsBase64(str string) bool
IsPort(str string) bool
IsURL(str string) bool
IsASCII(str string) bool
IsPrintableASCII(str string) bool
IsEmail(str string) bool
IsWinPath(str string) bool
IsUnixPath(str string) bool
IsSemver(str string) bool
IsFullWidth(str string) bool
IsHalfWidth(str string) bool
IsHash(str, algorithm string) bool
IsMAC(str string) bool
IsTime(str string, format string) bool
IsRFC3339Time(str string) bool
IsRFC3339WithoutZoneTime(str string) bool
IsJSON(str string) bool
IsUTFLetter(str string) bool
IsUTFLetterNumeric(str string) bool
IsHexcolor(str string) bool
IsRGBcolor(str string) bool
IsRGBAcolor(str string) bool
IsLowerCase(str string) bool
IsUpperCase(str string) bool
```

### has
```go
HasLowerCase(str string) bool
HasUpperCase(str string) bool
```

## LICENSE
vvalidator source code is licensed under the [MIT](https://github.com/syyongx/vvalidator/blob/master/LICENSE) Licence.
