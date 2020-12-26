package apiware

import (
	"errors"
	"net/http"
	// "github.com/valyala/fasthttp"
)

type (
	// Apiware binds request paramters
	Apiware struct {
		ParamNameMapper
		Pathdecoder
		Bodydecoder
		UseDefaultValues bool
	}

	// Pathdecoder parses path params function, return pathParams of KV type
	Pathdecoder func(urlPath, pattern string) (pathParams KV)
)

// New creates a new apiware engine.
// Parse and store the struct object, requires a struct pointer,
// if `paramNameMapper` is nil, `paramNameMapper=toSnake`,
// if `bodydecoder` is nil, `bodydecoder=bodyJONS`,
func New(pathdecoder Pathdecoder, bodydecoder Bodydecoder, paramNameMapper ParamNameMapper, useDefaultValues bool) *Apiware {
	return &Apiware{
		ParamNameMapper:  paramNameMapper,
		Pathdecoder:      pathdecoder,
		Bodydecoder:      bodydecoder,
		UseDefaultValues: useDefaultValues,
	}
}

// Register checks whether structs meet the requirements of apiware, and register them.
// note: requires a structure pointer.
func (a *Apiware) Register(structPointers ...interface{}) error {
	var errStr string
	for _, obj := range structPointers {
		err := Register(obj, a.ParamNameMapper, a.Bodydecoder, a.UseDefaultValues)
		if err != nil {
			errStr += err.Error() + "\n"
		}
	}
	if len(errStr) > 0 {
		return errors.New(errStr)
	}
	return nil
}

// Bind the net/http request params to the structure and validate.
// note: structPointer must be structure pointer.
func (a *Apiware) Bind(
	structPointer interface{},
	req *http.Request,
	pattern string,
) error {
	return Bind(structPointer, req, a.Pathdecoder(req.URL.Path, pattern))
}
