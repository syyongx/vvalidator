package vvalidator

var DefaultCode = 400

type Error struct {
	Message       string
	Code          int
	CustomMessage string
}

func NewError(message string, code int, customMessage string) Error {
	return Error{
		Message:       message,
		Code:          code,
		CustomMessage: customMessage,
	}
}
