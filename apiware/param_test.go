package apiware

import (
	"reflect"
	"testing"
)

func TestParseTags(t *testing.T) {
	var a reflect.StructTag = `param1:"<in:\"path\"> <name:test> <desc:test\\<1,2\\>> <required> <range::4>"`
	var param1 = a.Get("param1")
	var values1 = ParseTags(param1)
	t.Logf("values1:%#v", values1)

	var b reflect.StructTag = `  param2:"   <in:\"path\"> <name : test   > <desc:test\\<1,2\\>> <required:>    <range: :4  >  "   `
	var param2 = b.Get("param2")
	var values2 = ParseTags(param2)
	t.Logf("values2:%#v", values2)

	if values1["in"] != values2["in"] ||
		values1["desc"] != values2["desc"] ||
		values1["required"] != values2["required"] ||
		values1["range"] != values2["range"] ||
		values1["name"] != values2["name"] {

		t.Fail()
	}
}

func TestParseTags2(t *testing.T) {
	var a reflect.StructTag = `param:"<in:query> <name:p> <len: 1:10> <regexp: ^[\\w]*$>"`
	var param = a.Get("param")
	var values = ParseTags(param)
	t.Logf("values:%#v", values)
}
