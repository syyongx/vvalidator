package vvalidator

var DefaultCode = 400

type Error struct {
	Message string
	Code    int
	Note    string
}

func NewError(message string, code int, note string) *Error {
	return &Error{
		Message: message,
		Code:    code,
		Note:    note,
	}
}
