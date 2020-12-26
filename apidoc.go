// Copyright 2016 HenryLee. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// API automation documentation.

package aigo

import (
	"aigo/swagger"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"regexp"
	"strings"
)

type swaggerFS struct {
	jsonPath []byte
	http.FileSystem
}

func (s *swaggerFS) Open(name string) (http.File, error) {
	f, err := s.FileSystem.Open(name)
	if err == nil && name == "/index.html" {
		b, err := ioutil.ReadAll(f)
		f.Close()
		if err != nil {
			return f, err
		}
		b = bytes.Replace(b, []byte(`"/swagger.json"`), s.jsonPath, -1)
		info, err := swagger.AssetInfo("swagger-ui/index.html")
		if err != nil {
			return nil, err
		}
		return NewFile(b, &FileInfo{
			name:    "apidoc/index.html",
			size:    int64(len(b)),
			mode:    info.Mode(),
			modTime: info.ModTime(),
			isDir:   info.IsDir(),
			sys:     info.Sys(),
		}), err
	}
	return f, err
}

// register the API doc router.
func (e *Engine) regAPIdoc() {
	swaggerPath := e.swaggerPath()
	fs := FS(&swaggerFS{jsonPath: []byte("\"" + swaggerPath + "\""), FileSystem: swagger.AssetFS()})
	if e.config.APIdoc.NoLimit {
		e.IRoutes.nameStaticFS("APIdoc-Swagger", e.config.APIdoc.Path, fs)
		e.IRoutes.nameGET("APIdoc-Swagger-JSON", swaggerPath, newAPIdocJSONHandler())
	} else {
		allowApidoc := newIPFilter(e.config.APIdoc.Whitelist, e.config.APIdoc.RealIP)
		e.IRoutes.nameStaticFS("APIdoc-Swagger", e.config.APIdoc.Path, fs).Use(allowApidoc)
		e.IRoutes.nameGET("APIdoc-Swagger-JSON", swaggerPath, newAPIdocJSONHandler(), allowApidoc)
	}

	tip := `APIdoc's URL path is '` + e.config.APIdoc.Path
	if e.config.APIdoc.NoLimit {
		e.syslog.Criticalf(tip + `' [free access]`)
	} else if len(e.config.APIdoc.Whitelist) == 0 {
		e.syslog.Criticalf(tip + `' [no access]`)
	} else if e.config.APIdoc.RealIP {
		e.syslog.Criticalf(tip + `' [check real ip for filter]`)
	} else {
		e.syslog.Criticalf(tip + `' [check direct ip for filter]`)
	}
}

func newAPIdocJSONHandler() HandlerFunc {
	return func(ctx *Context) error {
		if ctx.engine.apidoc == nil {
			ctx.engine.initAPIdoc(ctx.R.Host)
		}
		ctx.engine.apidoc.Schemes = []string{ctx.Scheme()}
		ctx.engine.apidoc.Host = ctx.R.Host
		return ctx.JSON(200, ctx.engine.apidoc, true)
	}
}

func (e *Engine) swaggerPath() string {
	return strings.TrimRight(e.config.APIdoc.Path, "/") + "_swagger.json"
}

func (e *Engine) initAPIdoc(host string) {
	rootMuxAPI := e.IRoutes
	rootTag := &swagger.Tag{
		Name:        rootMuxAPI.Path(),
		Description: apiTagDesc(rootMuxAPI.Name()),
	}
	e.apidoc = &swagger.Swagger{
		Version: swagger.Version,
		Info: &swagger.Info{
			Title:          strings.Title(e.Name()) + " API",
			ApiVersion:     e.Version(),
			Description:    e.config.APIdoc.Desc,
			Contact:        &swagger.Contact{Email: e.config.APIdoc.Email},
			TermsOfService: e.config.APIdoc.TermsURL,
			License: &swagger.License{
				Name: e.config.APIdoc.License,
				Url:  e.config.APIdoc.LicenseURL,
			},
		},
		Host:     host,
		BasePath: "/",
		Tags:     []*swagger.Tag{rootTag},
		Schemes:  []string{"http", "https"},
		Paths:    map[string]map[string]*swagger.Opera{},
		// SecurityDefinitions: map[string]map[string]interface{}{},
		// Definitions:         map[string]Definition{},
		// ExternalDocs:        map[string]string{},
	}
	jsonPattern := e.swaggerPath()
	for _, child := range rootMuxAPI.Children() {
		// filter useless API
		if (child.relativePath == jsonPattern || strings.HasPrefix(child.relativePath, e.config.APIdoc.Path)) && child.HasMethod("GET") {
			continue
		}
		if !child.IsGroup() {
			addpath(child, rootTag)
			continue
		}
		childTag := &swagger.Tag{
			Name:        child.Path(),
			Description: apiTagDesc(child.Name()),
		}
		e.apidoc.Tags = append(e.apidoc.Tags, childTag)
		for _, grandson := range child.Children() {
			if !grandson.IsGroup() {
				addpath(grandson, childTag)
				continue
			}
			grandsonTag := &swagger.Tag{
				Name:        grandson.Path(),
				Description: apiTagDesc(grandson.Name()),
			}
			e.apidoc.Tags = append(e.apidoc.Tags, grandsonTag)
			for _, progeny := range grandson.Progeny() {
				if !progeny.IsGroup() {
					addpath(progeny, grandsonTag)
					continue
				}
			}
		}
	}
}

// 添加API操作项
func addpath(i *IRoutes, tag *swagger.Tag) {
	operas := map[string]*swagger.Opera{}
	pid := apiCreatePath(i.Path())
	summary := apiSummary(i.Name())
	desc := apiDesc(i.Notes())
	for _, method := range i.Methods() {
		if method == "CONNECT" || method == "TRACE" {
			continue
		}
		// if method == "WS" {
		// 	method = "GET"
		// }
		o := &swagger.Opera{
			Tags:        []string{tag.Name},
			Summary:     summary,
			Description: desc,
			OperationId: pid + "-" + method,
			Consumes:    swagger.CommonMIMETypes,
			Produces:    swagger.CommonMIMETypes,
			Responses:   make(map[string]*swagger.Resp, 1),
			// Security: []map[string][]string{},
		}

		for _, param := range i.ParamInfos() {
			p := &swagger.Parameter{
				In:          param.In,
				Name:        param.Name,
				Description: param.Desc,
				Required:    param.Required,
				// Items:       &Items{},
				// Schema:      &Schema{},
			}
			typ := swagger.ParamType(param.Model)
			switch p.In {
			case "cookie":
				continue
			default:
				switch typ {
				case "file":
					o.Consumes = []string{"multipart/form-data"}
					p.Type = typ

				case "array":
					subtyp, first, count := swagger.SliceInfo(param.Model)
					switch subtyp {
					case "object":
						ref := apiDefinitions(i, p.Name, method, param.Model)
						p.Schema = &swagger.Schema{
							Type: typ,
							Items: &swagger.Items{
								Ref: "#/definitions/" + ref,
							},
						}

					default:
						p.Type = typ
						p.Items = &swagger.Items{
							Type:    subtyp,
							Default: first,
						}
						if count > 0 {
							p.Items.Enum = param.Model
						}
						p.CollectionFormat = "multi"
					}

				case "object":
					ref := apiDefinitions(i, p.Name, method, param.Model)
					p.Schema = &swagger.Schema{
						Type: typ,
						Ref:  "#/definitions/" + ref,
					}

				default:
					p.Type = typ
					p.Format = fmt.Sprintf("%T", param.Model)
					p.Default = param.Model
				}
			}

			o.Parameters = append(o.Parameters, p)
		}

		// static file
		if strings.HasSuffix(pid, "/{filepath}") {
			o.Parameters = append(o.Parameters, &swagger.Parameter{
				In:          "path",
				Name:        "filepath",
				Type:        swagger.ParamType("*"),
				Description: "any static path or file",
				Required:    true,
				Format:      fmt.Sprintf("%T", "*"),
				Default:     "",
			})
		}

		operas[strings.ToLower(method)] = o
	}
	if _operas, ok := i.engine.apidoc.Paths[pid]; ok {
		for k, v := range operas {
			_operas[k] = v
		}
	} else {
		i.engine.apidoc.Paths[pid] = operas
	}
}

func apiDefinitions(i *IRoutes, pname, method string, format interface{}) (ref string) {
	upath := i.Path()
	ref = strings.Replace(path.Join(upath[1:], pname, method), "/", "@", -1)
	def := &swagger.Definition{
		Type: "object",
		Xml:  &swagger.Xml{Name: ref},
	}
	def.Properties = swagger.CreateProperties(format)
	if i.engine.apidoc.Definitions == nil {
		i.engine.apidoc.Definitions = map[string]*swagger.Definition{}
	}
	i.engine.apidoc.Definitions[ref] = def
	return
}

var (
	pathWildcardRegexp = regexp.MustCompile(`/\*[^/]*`)
	pathColonRegexp    = regexp.MustCompile(`/:[^/]*`)
)

func apiCreatePath(u string) string {
	for _, wildcard := range pathWildcardRegexp.FindAllString(u, -1) {
		u = strings.Replace(u, wildcard, "/{"+wildcard[2:]+"}", -1)
	}
	for _, colon := range pathColonRegexp.FindAllString(u, -1) {
		u = strings.Replace(u, colon, "/{"+colon[2:]+"}", -1)
	}
	return u
}

func apiTagDesc(desc string) string {
	return strings.TrimSpace(desc)
}

func apiSummary(desc string) string {
	return strings.TrimSpace(strings.Split(strings.TrimSpace(desc), "\n")[0])
}

func apiDesc(notes []Notes) string {
	var desc string
	count := len(notes)
	for i, n := range notes {
		if count > 1 {
			desc += fmt.Sprintf("\n\n======================= Handler %d =======================", i)
		}
		if n.Note != "" {
			desc += fmt.Sprintf("\nNote: %s", strings.TrimSpace(n.Note))
		} else {
			desc += "\nNote:"
		}
		if n.Return != nil {
			b, _ := json.MarshalIndent(n.Return, "", "  ")
			desc += fmt.Sprintf("\nReturn: %s", b)
		} else {
			desc += "\nReturn:"
		}
	}
	if desc != "" {
		return "<pre style=\"line-height:18px;\">" + strings.TrimSpace(desc) + "</pre>"
	}
	return ""
}

// newIPFilter creates middleware that intercepts the specified IP prefix.
func newIPFilter(whitelist []string, realIP bool) HandlerFunc {
	var noAccess bool
	var match []string
	var prefix []string

	if len(whitelist) == 0 {
		noAccess = true
	} else {
		for _, s := range whitelist {
			if strings.HasSuffix(s, "*") {
				prefix = append(prefix, s[:len(s)-1])
			} else {
				match = append(match, s)
			}
		}
	}

	return func(ctx *Context) error {
		if noAccess {
			ctx.Error(http.StatusForbidden, "no access")
			return nil
		}

		var ip string
		if realIP {
			ip = ctx.RealIP()
		} else {
			ip = ctx.IP()
		}
		for _, ipMatch := range match {
			if ipMatch == ip {
				ctx.Next()
				return nil
			}
		}
		for _, ipPrefix := range prefix {
			if strings.HasPrefix(ip, ipPrefix) {
				ctx.Next()
				return nil
			}
		}
		ctx.Error(http.StatusForbidden, "not allow to access: "+ip)
		return nil
	}
}
