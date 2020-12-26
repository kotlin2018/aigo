package apiware

// Error a formatted error type
type Error struct {
	Api    string `json:"api"`
	Param  string `json:"param"`
	Reason string `json:"reason"`
}

// NewError creates *Error
func NewError(api string, param string, reason string) *Error {
	return &Error{
		Api:    api,
		Param:  param,
		Reason: reason,
	}
}

var _ error = new(Error)

// Error implements error interface
func (e *Error) Error() string {
	return "[apiware] " + e.Api + " | " + e.Param + " | " + e.Reason
}
