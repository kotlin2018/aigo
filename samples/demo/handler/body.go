package handler

import (
	"aigo"
)

type Body struct {
	Json map[string]interface{} `param:"<in:body>"`
}

func (b *Body) Serve(ctx *aigo.Context) error {
	return ctx.JSON(200, b.Json, true)
}
