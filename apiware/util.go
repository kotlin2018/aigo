package apiware

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

func toSnake(s string) string {
	buf := bytes.NewBufferString("")
	for i, v := range s {
		if i > 0 && v >= 'A' && v <= 'Z' {
			buf.WriteRune('_')
		}
		buf.WriteRune(v)
	}
	return strings.ToLower(buf.String())
}

func interfaceToSnake(f interface{}) string {
	t := reflect.TypeOf(f)
	for {
		c := false
		switch t.Kind() {
		case reflect.Array, reflect.Chan, reflect.Map, reflect.Ptr, reflect.Slice:
			t = t.Elem()
			c = true
		}
		if !c {
			break
		}
	}
	return toSnake(t.Name())
}

func snakeToUpperCamel(s string) string {
	buf := bytes.NewBufferString("")
	for _, v := range strings.Split(s, "_") {
		if len(v) > 0 {
			buf.WriteString(strings.ToUpper(v[:1]))
			buf.WriteString(v[1:])
		}
	}
	return buf.String()
}

func bodyJONS(dest reflect.Value, body []byte) error {
	var err error
	if dest.Kind() == reflect.Ptr {
		err = json.Unmarshal(body, dest.Interface())
	} else {
		err = json.Unmarshal(body, dest.Addr().Interface())
	}
	return err
}

type (
	KV interface {
		Get(k string) (v string, found bool)
	}
	Map map[string]string
)

func (m Map) Get(k string) (string, bool) {
	v, found := m[k]
	return v, found
}
