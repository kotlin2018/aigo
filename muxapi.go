package aigo

import (
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
)

type (
	// 这是一个路由表,类似于Go语言 net/http 包的 serveMux, 为请求的api，分配对应的handler
	IRoutes struct {
		name       		string
		relativePath    string
		path       		string
		methods    		[]string
		handlers   		[]Handler
		paramInfos 		[]ParamInfo
		notes      		[]Notes
		parent     		*IRoutes
		children   		[]*IRoutes
		engine     		*Engine
	}
	//(http.Request)请求的方法类型,例如:GET、POST、PUT、PATCH、DELETED...
	MethodType string
)

// RESTFul 方法的切片集合
var RESTFulMethodList = []string{
	"CONNECT",
	"DELETE",
	"GET",
	"HEAD",
	"OPTIONS",
	"PATCH",
	"POST",
	"PUT",
	"TRACE",
}

func newMuxAPI(engine *Engine, name string, methodType MethodType, relativePath string, handlers ...Handler) *IRoutes {
	iRoutes:= &IRoutes{
		name:       	 name,
		relativePath:    relativePath,
		methods:   		 methodType.Methods(),
		handlers:   	 handlers,
		paramInfos: 	 []ParamInfo{},
		notes:      	 []Notes{},
		children:   	 []*IRoutes{},
		engine:      	 engine,
	}
	return iRoutes
}

//1、解析出方法列表,例如：CONNECT、DELETE、GET、HEAD、 OPTIONS、 PATCH、POST、PUT、TRACE
func (m *MethodType) Methods() []string {
	s := strings.ToUpper(string(*m))
	if strings.Contains(s, "*") {
		methods := make([]string, len(RESTFulMethodList))
		copy(methods, RESTFulMethodList)
		return methods
	}
	methods := []string{}
	for _, method := range RESTFulMethodList {
		if strings.Contains(s, method) {
			methods = append(methods, method)
		}
	}
	return methods
}

//2、检查指定的方法是否存在。
func (i *IRoutes) HasMethod(method string) bool {
	method = strings.ToUpper(method)
	for _, m := range i.methods {
		if method == m {
			return true
		}
	}
	return false
}

//3、将具有该名称的从属节点添加到当前muxAPI分组节点。handlers不能为空
func (i *IRoutes) api(name string, methods MethodType, pattern string, handlers ...Handler) *IRoutes {
	for _, h := range handlers {
		if h == nil {
			errStr := "handler cannot be nil:" + reflect.TypeOf(h).String()
			i.engine.Log().Panicf("%s\n", errStr)
		}
	}
	pattern = path.Join("/", pattern)
	var child = newMuxAPI(i.engine, name, methods, pattern, handlers...)
	i.children = append(i.children, child)
	child.parent = i
	return child
}

// Group adds a subordinate subgroup node to the current muxAPI grouping node.
// notes: handler cannot be nil.
func (i *IRoutes) Group(relativePath string, handlers ...Handler) *IRoutes {
	return i.api("", "", relativePath, handlers...)
}

// NamedGroup adds a subordinate subgroup node with the name to the current muxAPI grouping node.
// notes: handler cannot be nil.
func (i *IRoutes) namedGroup(name string, pattern string, handlers ...Handler) *IRoutes {
	return i.api(name, "", pattern, handlers...)
}

// IsGroup returns whether the muxapi node is group or not.
func (i *IRoutes) IsGroup() bool {
	return len(i.methods) == 0
}

// API adds a subordinate node to the current muxAPI grouping node.
// notes: handler cannot be nil.
func (i *IRoutes) Any(methods MethodType, relativePath string, handlers ...Handler) *IRoutes {
	return i.api("", methods, relativePath, handlers...)
}

// GET is a shortcut for muxAPI.API("GET", pattern, handlers...)
func (i *IRoutes) GET(pattern string, handlers ...Handler) *IRoutes {
	return i.Any("GET", pattern, handlers...)
}

// HEAD is a shortcut for muxAPI.API("HEAD", pattern, handlers...)
func (i *IRoutes) HEAD(pattern string, handlers ...Handler) *IRoutes {
	return i.Any("HEAD", pattern, handlers...)
}

// OPTIONS is a shortcut for muxAPI.API("OPTIONS", pattern, handlers...)
func (i *IRoutes) OPTIONS(pattern string, handlers ...Handler) *IRoutes {
	return i.Any("OPTIONS", pattern, handlers...)
}

// POST is a shortcut for muxAPI.API("POST", pattern, handlers...)
func (i *IRoutes) POST(pattern string, handlers ...Handler) *IRoutes {
	return i.Any("POST", pattern, handlers...)
}

// PUT is a shortcut for muxAPI.API("PUT", pattern, handlers...)
func (i *IRoutes) PUT(pattern string, handlers ...Handler) *IRoutes {
	return i.Any("PUT", pattern, handlers...)
}

// PATCH is a shortcut for muxAPI.API("PATCH", pattern, handlers...)
func (i *IRoutes) PATCH(pattern string, handlers ...Handler) *IRoutes {
	return i.Any("PATCH", pattern, handlers...)
}

// DELETE is a shortcut for muxAPI.API("DELETE", pattern, handlers...)
func (i *IRoutes) DELETE(pattern string, handlers ...Handler) *IRoutes {
	return i.Any("DELETE", pattern, handlers...)
}

// NamedGET is a shortcut for muxAPI.NamedAPI(name, "GET", pattern, handlers...)
func (i *IRoutes) nameGET(name string, pattern string, handlers ...Handler) *IRoutes {
	return i.api(name, "GET", pattern, handlers...)
}

// NamedHEAD is a shortcut for muxAPI.NamedAPI(name, "HEAD", pattern, handlers...)
func (i *IRoutes) nameHEAD(name string, pattern string, handlers ...Handler) *IRoutes {
	return i.api(name, "HEAD", pattern, handlers...)
}

// NamedOPTIONS is a shortcut for muxAPI.NamedAPI(name, "OPTIONS", pattern, handlers...)
func (i *IRoutes) nameOPTIONS(name string, pattern string, handlers ...Handler) *IRoutes {
	return i.api(name, "OPTIONS", pattern, handlers...)
}

// NamedPOST is a shortcut for muxAPI.NamedAPI(name, "POST", pattern, handlers...)
func (i *IRoutes) namePOST(name string, pattern string, handlers ...Handler) *IRoutes {
	return i.api(name, "POST", pattern, handlers...)
}

// NamedPUT is a shortcut for muxAPI.NamedAPI(name, "PUT", pattern, handlers...)
func (i *IRoutes) namePUT(name string, pattern string, handlers ...Handler) *IRoutes {
	return i.api(name, "PUT", pattern, handlers...)
}

// NamedPATCH is a shortcut for muxAPI.NamedAPI(name, "PATCH", pattern, handlers...)
func (i *IRoutes) namePATCH(name string, pattern string, handlers ...Handler) *IRoutes {
	return i.api(name, "PATCH", pattern, handlers...)
}

// NamedDELETE is a shortcut for muxAPI.NamedAPI(name, "DELETE", pattern, handlers...)
func (i *IRoutes) nameDELETE(name string, pattern string, handlers ...Handler) *IRoutes {
	return i.api(name, "DELETE", pattern, handlers...)
}

// FilepathKey path key for static router pattern.
const FilepathKey = "filepath"

// NamedStaticFS serves files from the given file system fs.
// The pattern must end with "/*filepath", files are then served from the local
// pattern /defined/root/dir/*filepath.
// For example if root is "/etc" and *filepath is "passwd", the local file
// "/etc/passwd" would be served.
// Internally a http.FileServer is used, therefore http.NotFound is used instead
// of the Router's NotFound handler.
// To use the operating system's file system implementation,
// use http.Dir:
//     frame.StaticFS("/src/*filepath", Dir("/var/www", true, true)
func (i *IRoutes) nameStaticFS(name, pattern string, fs FileSystem) *IRoutes {
	if fs == nil {
		errStr := "For file server, fs (http.FileSystem) cannot be nil"
		i.engine.Log().Panicf("%s\n", errStr)
	}
	if len(pattern) < 10 || pattern[len(pattern)-10:] != "/*"+FilepathKey {
		pattern = path.Join(pattern, "/*"+FilepathKey)
	}
	handler := func(fileServer Handler) Handler {
		return HandlerFunc(func(ctx *Context) error {
			ctx.R.URL.Path = ctx.pathParams.ByName(FilepathKey)
			return fileServer.Serve(ctx)
		})
	}(global.fsManager.FileServer(fs))
	return i.api(name, "GET", pattern, handler)
}

// StaticFS is similar to NamedStaticFS, but no name.
func (i *IRoutes) StaticFS(pattern string, fs FileSystem) *IRoutes {
	return i.nameStaticFS("fileserver", pattern, fs)
}

// NamedStatic is similar to NamedStaticFS, but the second parameter is the local file path.
func (i *IRoutes) nameStatic(name, pattern string, root string, nocompressAndNocache ...bool) *IRoutes {
	os.MkdirAll(root, 0777)
	return i.nameStaticFS(name, pattern, DirFS(root, nocompressAndNocache...))
}

// Static is similar to NamedStatic, but no name.
func (i *IRoutes) Static(pattern string, root string, nocompressAndNocache ...bool) *IRoutes {
	return i.nameStatic(root, pattern, root, nocompressAndNocache...)
}

// Use inserts the middlewares at the left end of the node's handler chain.
// notes: handler cannot be nil.
func (i *IRoutes) Use(handlers ...Handler) *IRoutes {
	_handlers := make([]Handler, len(handlers))
	for k, h := range handlers {
		if h == nil {
			errStr := "For using middleware, handler cannot be nil:" + reflect.TypeOf(h).String()
			i.engine.Log().Panicf("%s\n", errStr)
		}
		if !IsHandlerWithoutPath(h, i.engine.config.Router.NoDefaultParams) {
			errStr := "For using middleware, the handlers can not bind the path parameter:" + reflect.TypeOf(h).String()
			i.engine.Log().Panicf("%s\n", errStr)
		}
		_handlers[k] = h
	}
	i.handlers = append(_handlers, i.handlers...)
	return i
}

// comb mux.handlers, mux.paramInfos, mux.notes and mux.path,.
// sort children by path.
// note: can only be executed once before HTTP serving.
func (i *IRoutes) comb() {
	i.paramInfos = i.paramInfos[:0]
	i.notes = i.notes[:0]
	for k, handler := range i.handlers {
		h, err := ToAPIHandler(handler, i.engine.config.Router.NoDefaultParams)
		if err != nil {
			if err == ErrNotStructPtr || err == ErrNoParamHandler {
				// Get the information for apidoc
				if doc, ok := handler.(APIDoc); ok {
					docinfo := doc.Doc()
					if docinfo.Note != "" || docinfo.Return != nil {
						i.notes = append(i.notes, Notes{Note: docinfo.Note, Return: docinfo.Return})
					}
					for _, param := range docinfo.MoreParams {
						// The path parameter must be a required parameter.
						if param.In == "path" {
							param.Required = true
						}
						i.paramInfos = append(i.paramInfos, param)
					}
				}
				continue
			}
			errStr := "[Faygo-ToAPIHandler] " + err.Error()
			i.engine.Log().Panicf("%s\n", errStr)
		}

		if h.paramsAPI.MaxMemory() == defaultMultipartMaxMemory {
			h.paramsAPI.SetMaxMemory(i.engine.config.multipartMaxMemory)
		}
		// Get the information for apidoc
		docinfo := h.Doc()
		if docinfo.Note != "" || docinfo.Return != nil {
			i.notes = append(i.notes, Notes{Note: docinfo.Note, Return: docinfo.Return})
		}
		for _, param := range docinfo.MoreParams {
			// The path parameter must be a required parameter.
			if param.In == "path" {
				param.Required = true
			}
			i.paramInfos = append(i.paramInfos, param)
		}
		i.handlers[k] = h
	}
	// check path params defined, and panic if there is any error.
	i.checkPathParams()
	i.path = i.relativePath
	if i.parent != nil {
		i.path = path.Join(i.parent.path, i.path)
		i.notes = append(i.parent.notes, i.notes...)
		i.paramInfos = append(i.parent.paramInfos, i.paramInfos...)
		i.handlers = append(i.parent.handlers, i.handlers...)
	}

	// Get distinct and sorted parameters information.
	i.paramInfos = distinctAndSortedParamInfos(i.paramInfos)

	if len(i.children) == 0 {
		// Check for body parameter conflicts
		i.checkBodyParamConflicts()
	} else {
		for _, child := range i.children {
			child.comb()
		}
		sort.Sort(MuxAPIs(i.children))
	}
}

// check path params defined, and panic if there is any error.
func (i *IRoutes) checkPathParams() {
	var numPathParams uint8
	for _, paramInfo := range i.paramInfos {
		if paramInfo.In != "path" {
			continue
		}
		if !strings.Contains(i.relativePath, "/:"+paramInfo.Name) && !strings.Contains(i.relativePath, "/*"+paramInfo.Name) {
			i.engine.Log().Panicf(
				"[Faygo-checkPathParams] the router pattern `%s` does not match the path param:\n%#v",
				i.relativePath,
				paramInfo,
			)
		}
		numPathParams++
	}
	if countPathParams(i.relativePath) < numPathParams {
		i.engine.Log().Panicf(
			"[Faygo-checkPathParams] the router pattern `%s` does not match the path params:\n%#v",
			i.relativePath,
			i.paramInfos,
		)
	}
}

// check path params defined, and panic if there is any error.
func (i *IRoutes) checkBodyParamConflicts() {
	var hasBody bool
	var hasFormData bool
	for _, paramInfo := range i.paramInfos {
		switch paramInfo.In {
		case "formData":
			if hasBody {
				errStr := "[Faygo-checkBodyParamConflicts] handler struct tags of `in(formData)` and `in(body)` can not exist at the same time:\nURL path: " + i.path
				i.engine.Log().Panicf("%s\n", errStr)
			}
			hasFormData = true
		case "body":
			if hasFormData {
				errStr := "[Faygo-checkBodyParamConflicts] handler struct tags of `in(formData)` and `in(body)` can not exist at the same time:\nURL path: " + i.path
				i.engine.Log().Panicf("%s\n", errStr)
			}
			if hasBody {
				errStr := "[Faygo-checkBodyParamConflicts] there should not be more than one handler struct tag `in(body)`:\nURL path: " + i.path
				i.engine.Log().Panicf("%s\n", errStr)
			}
			hasBody = true
		}
	}
}

// Methods returns the methods of muxAPI node.
func (i *IRoutes) Methods() []string {
	return i.methods
}

// Path returns the path of muxAPI node.
func (i *IRoutes) Path() string {
	return i.path
}

// Name returns the name of muxAPI node.
func (i *IRoutes) Name() string {
	return i.name
}

// ParamInfos returns the paramInfos of muxAPI node.
func (i *IRoutes) ParamInfos() []ParamInfo {
	return i.paramInfos
}

// Notes returns the notes of muxAPI node.
func (i *IRoutes) Notes() []Notes {
	return i.notes
}

// Parent returns the parent of muxAPI node.
func (i *IRoutes) Parent() *IRoutes {
	return i.parent
}

// Children returns the children of muxAPI node.
func (i *IRoutes) Children() []*IRoutes {
	return i.children
}

// Progeny returns an ordered list of all subordinate nodes.
func (i *IRoutes) Progeny() []*IRoutes {
	nodes := []*IRoutes{}
	for _, child := range i.children {
		child.family(&nodes)
	}
	return nodes
}

// Family returns an ordered list of tree nodes.
func (i *IRoutes) Family() []*IRoutes {
	nodes := []*IRoutes{i}
	for _, child := range i.children {
		child.family(&nodes)
	}
	return nodes
}

func (i *IRoutes) family(nodes *[]*IRoutes) {
	*nodes = append(*nodes, i)
	for _, child := range i.children {
		child.family(nodes)
	}
}

// HandlerProgeny returns an ordered list of subordinate nodes used to register router.
func (i *IRoutes) HandlerProgeny() []*IRoutes {
	if !i.IsGroup() {
		return []*IRoutes{i}
	}
	nodes := []*IRoutes{}
	for _, child := range i.children {
		nodes = append(nodes, child.HandlerProgeny()...)
	}
	return nodes
}

// MuxAPIs is the array of muxAPIs for sorting
type MuxAPIs []*IRoutes

// Len returns the length of muxAPIs
func (ends MuxAPIs) Len() int {
	return len(ends)
}

// Less returns the smaller muxAPI.
func (ends MuxAPIs) Less(i, j int) bool {
	return ends[i].path <= ends[j].path
}

// Swap swaps the two muxAPIs
func (ends MuxAPIs) Swap(i, j int) {
	ends[i], ends[j] = ends[j], ends[i]
}
