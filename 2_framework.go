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

package aigo

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aigo/logging"
	"aigo/logging/color"
	"aigo/session"
	"aigo/swagger"
)

// Framework is the faygo web framework.
type Engine struct {
	// name of the application
	name string
	// version of the application
	version string
	config  Config
	// root muxAPI node
	*IRoutes
	muxesForRouter MuxAPIs
	// called before the route is matched
	filter         HandlerChain
	servers        []*Server
	running        bool
	buildOnce      sync.Once
	lock           sync.RWMutex
	sessionManager *session.Manager
	// for framework
	syslog *logging.Logger
	// for user bissness
	bizlog         *logging.Logger
	apidoc         *swagger.Swagger
	dynamicSrcTree map[string]*node // dynamic resource router tree
	staticSrcTree  map[string]*node // dynamic resource router tree
	// Redirect from 'http://hostname:port1' to 'https://hostname:port2'
	httpRedirectHttps bool
	// One of the https ports to be listened
	httpsPort string
	// Enables automatic redirection if the current route can't be matched but a
	// handler for the path with (without) the trailing slash exists.
	// For example if /foo/ is requested but a route only exists for /foo, the
	// client is redirected to /foo with http status code 301 for GET requests
	// and 307 for all other request methods.
	redirectTrailingSlash bool
	// If enabled, the router tries to fix the current request path, if no
	// handle is registered for it.
	// First superfluous path elements like ../ or // are removed.
	// Afterwards the router does a case-insensitive lookup of the cleaned path.
	// If a handle can be found for this route, the router makes a redirection
	// to the corrected path with status code 301 for GET requests and 307 for
	// all other request methods.
	// For example /FOO and /..//Foo could be redirected to /foo.
	// redirectTrailingSlash is independent of this option.
	redirectFixedPath bool
	// If enabled, the router checks if another method is allowed for the
	// current route, if the current request can not be routed.
	// If this is the case, the request is answered with 'Method Not Allowed'
	// and HTTP status code 405.
	// If no other Method is allowed, the request is delegated to the NotFound
	// handler.
	handleMethodNotAllowed bool
	// If enabled, the router automatically replies to OPTIONS requests.
	// Custom OPTIONS handlers take priority over automatic replies.
	handleOPTIONS bool
	contextPool   sync.Pool
}

// Make sure the Framework conforms with the http.Handler interface
var _ http.Handler = new(Engine)

// newFramework uses the faygo web framework to create a new application.
func newFramework(config *Config, name string, version []string) *Engine {
	mutexNewApp.Lock()
	defer mutexNewApp.Unlock()
	var frame = new(Engine)

	frame.name = strings.TrimSpace(name)
	if len(version) > 0 && len(version[0]) > 0 {
		frame.version = strings.TrimSpace(version[0])
	}

	id := frame.NameWithVersion()
	if _, ok := GetFrame(id); ok {
		Fatalf("There are two applications with exactly the same name and version: %s", id)
	}

	if config == nil {
		config = newConfigFromFileAndCheck(frame.ConfigFilename())
	} else {
		config.check()
	}
	frame.setConfig(config)

	frame.redirectTrailingSlash = frame.config.Router.RedirectTrailingSlash
	frame.redirectFixedPath = frame.config.Router.RedirectFixedPath
	frame.handleMethodNotAllowed = frame.config.Router.HandleMethodNotAllowed
	frame.handleOPTIONS = frame.config.Router.HandleOPTIONS
	frame.contextPool = sync.Pool{
		New: func() interface{} {
			ctx := &Context{
				engine:         frame,
				enableGzip:    global.config.Gzip.Enable,
				enableSession: frame.config.Session.Enable,
				enableXSRF:    frame.config.XSRF.Enable,
			}
			ctx.W = &Response{context: ctx}
			return ctx
		},
	}
	frame.initSysLogger()
	frame.initBizLogger()
	frame.IRoutes = newMuxAPI(frame, "root", "", "/")
	addFrame(frame)
	return frame
}

var (
	mutexNewApp   sync.Mutex
	mutexForBuild sync.Mutex
)

func (e *Engine) setConfig(config *Config) {
	e.config = *config
}

// Name returns the name of the application
func (e *Engine) Name() string {
	return e.name
}

// Version returns the version of the application
func (e *Engine) Version() string {
	return e.version
}

// NameWithVersion returns the name with version
func (e *Engine) NameWithVersion() string {
	if len(e.version) == 0 {
		return e.name
	}
	return e.name + "_" + e.version
}

// Config returns the framework's config copy.
func (e *Engine) Config() Config {
	return e.config
}

// ConfigFilename returns the framework's config file name.
func (e *Engine) ConfigFilename() string {
	return configDir + "/" + e.NameWithVersion() + ".ini"
}

// Run starts the web service.
func (e *Engine) Run() {
	if e.Running() {
		return
	}
	global.beforeRun()
	go e.run()
	select {}
}

// Running returns whether the frame service is running.
func (e *Engine) Running() bool {
	e.lock.RLock()
	defer e.lock.RUnlock()
	return e.running
}

func (e *Engine) run() {
	e.lock.Lock()
	e.build()
	e.running = true
	count := len(e.servers)
	for i := 0; i < count; i++ {
		go e.servers[i].run()
	}
	e.lock.Unlock()
}

func (e *Engine) build() {
	e.buildOnce.Do(func() {
		// Make sure that the initialization logs for multiple applications are printed in sequence
		mutexForBuild.Lock()
		defer mutexForBuild.Unlock()

		// register the default MuxAPIs
		{
			// apidoc
			if e.config.APIdoc.Enable {
				e.regAPIdoc()
			}
			// static
			e.presetSystemMuxes()
		}

		// register router
		if e.dynamicSrcTree == nil {
			e.dynamicSrcTree = make(map[string]*node)
		}
		if e.staticSrcTree == nil {
			e.staticSrcTree = make(map[string]*node)
		}
		for _, api := range e.MuxAPIsForRouter() {
			handle := e.makeHandle(api.handlers)
			for _, method := range api.methods {
				if api.path[0] != '/' {
					Panic("path must begin with '/' in path '" + api.path + "'")
				}
				var root *node
				if strings.HasSuffix(api.path, "/*"+FilepathKey) &&
					api.path != "/apidoc/*"+FilepathKey &&
					api.path != "/upload/*"+FilepathKey &&
					api.path != "/static/*"+FilepathKey {
					// custom static
					root = e.staticSrcTree[method]
					if root == nil {
						root = new(node)
						e.staticSrcTree[method] = root
					}
				} else {
					// dynamic or default static
					root = e.dynamicSrcTree[method]
					if root == nil {
						root = new(node)
						e.dynamicSrcTree[method] = root
					}
				}
				root.addRoute(api.path, handle)
				e.syslog.Criticalf("\x1b[46m[SYS]\x1b[0m %7s | %-30s", method, api.path)
			}
		}

		// new server
		nameWithVersion := e.NameWithVersion()
		for i, netType := range e.config.NetTypes {
			srv := &Server{
				nameWithVersion: nameWithVersion,
				netType:         netType,
				tlsCertFile:     e.config.TLSCertFile,
				tlsKeyFile:      e.config.TLSKeyFile,
				letsencryptDir:  e.config.LetsencryptDir,
				unixFileMode:    e.config.unixFileMode,
				Server: &http.Server{
					Addr:         e.config.Addrs[i],
					Handler:      e,
					ReadTimeout:  e.config.ReadTimeout,
					WriteTimeout: e.config.WriteTimeout,
				},
				log: e.syslog,
			}
			if e.config.HttpRedirectHttps && srv.isHttps() {
				e.httpRedirectHttps = true
				e.httpsPort = srv.port()
			}
			e.servers = append(e.servers, srv)
		}

		// register session
		e.registerSession()
	})
}

// shutdown closes the frame service gracefully.
func (e *Engine) shutdown(ctxTimeout context.Context) (graceful bool) {
	e.lock.Lock()
	defer e.lock.Unlock()
	if !e.running {
		return true
	}
	var flag int32 = 1
	count := new(sync.WaitGroup)
	for _, server := range e.servers {
		count.Add(1)
		go func(srv *Server) {
			if err := srv.Shutdown(ctxTimeout); err != nil {
				atomic.StoreInt32(&flag, 0)
				e.Log().Errorf("[shutdown-%s] %s", e.NameWithVersion(), err.Error())
			}
			count.Done()
		}(server)
	}
	count.Wait()
	e.running = false
	e.CloseLog()
	return flag == 1
}

// Log returns the logger used by the user bissness.
func (e *Engine) Log() *logging.Logger {
	return e.bizlog
}

// CloseLog closes loggers.
func (e *Engine) CloseLog() {
	e.bizlog.Close()
	e.syslog.Close()
}

// MuxAPIsForRouter get an ordered list of nodes used to register router.
func (e *Engine) MuxAPIsForRouter() []*IRoutes {
	if e.muxesForRouter == nil {
		// comb mux.handlers, mux.paramInfos, mux.returns and mux.path,.
		e.IRoutes.comb()

		e.muxesForRouter = e.IRoutes.HandlerProgeny()
	}
	return e.muxesForRouter
}

// ************************************ RESRFull API ************************************************************
// Filter operations that are called before the route is matched.
//func (frame *Framework) Filter(fn ...HandlerFunc) *Framework {
//	handlers := make([]Handler, len(fn))
//	for i, h := range fn {
//		handlers[i] = h
//	}
//	frame.filter = append(handlers, frame.filter...)
//	return frame
//}

//1、注册中间件
func (e *Engine) Use(middleware ...HandlerFunc) *Engine {
	handlers := make([]Handler, len(middleware))
	for i, h := range middleware {
		handlers[i] = h
	}
	e.filter = append(handlers, e.filter...)
	return e
}


//2、添加函数类型的中间件到根muxAPI。用于以树型方式注册路由器。
func (e *Engine) RouteTree(children ...*IRoutes) *IRoutes {
	e.IRoutes.children = append(e.IRoutes.children, children...)
	for _, child := range children {
		child.parent = e.IRoutes
	}
	return e.IRoutes
}

//3、创建分组路由
func (e *Engine) Group(relativePath string, children ...*IRoutes) *IRoutes {
	return e.newNameGroup("", relativePath, children...)
}

//4、创建一个隔离的muxAPI节点。输入RESTFull 方法名(例如:GET,POST,DELETE,PUT...)创建对应的路由api,
func (e *Engine) Any(methodName MethodType, relativePath string, handlers ...Handler) *IRoutes {
	return e.newNameAPI("", methodName, relativePath, handlers...)
}

//5、使用该名称创建一个隔离的分组muxAPI节点。
func (e *Engine) newNameGroup(name,relativePath string, children ...*IRoutes) *IRoutes {
	group := e.newNameAPI(name, "", relativePath)
	group.children = append(group.children, children...)
	for _, child := range children {
		child.parent = group
	}
	return group
}

//6、使用该名称创建一个隔离的muxAPI节点。
func (e *Engine) newNameAPI(name string, methodName MethodType, relativePath string, handlers ...Handler) *IRoutes {
	return newMuxAPI(e, name, methodName, relativePath, handlers...)
}

// RESTFull GET 方法
func (e *Engine) GET(relativePath string, handlers ...Handler) *IRoutes {
	return e.Any("GET", relativePath, handlers...)
}

// RESTFull HEAD 方法
func (e *Engine) HEAD(relativePath string, handlers ...Handler) *IRoutes {
	return e.Any("HEAD", relativePath, handlers...)
}

// RESTFull OPTIONS 方法
func (e *Engine) OPTIONS(relativePath string, handlers ...Handler) *IRoutes {
	return e.Any("OPTIONS", relativePath, handlers...)
}

// RESTFull POST 方法
func (e *Engine) POST(relativePath string, handlers ...Handler) *IRoutes {
	return e.Any("POST", relativePath, handlers...)
}

// RESTFull PUT 方法
func (e *Engine) PUT(relativePath string, handlers ...Handler) *IRoutes {
	return e.Any("PUT", relativePath, handlers...)
}

// RESTFull PATCH 方法
func (e *Engine) PATCH(relativePath string, handlers ...Handler) *IRoutes {
	return e.Any("PATCH", relativePath, handlers...)
}

// RESTFull PATCH 方法
func (e *Engine) DELETE(relativePath string, handlers ...Handler) *IRoutes {
	return e.Any("DELETE", relativePath, handlers...)
}

// 根据输入的方法RESTFull方法名 "GET" 创建GET方法
func (e *Engine) newNameGET(name,relativePath string, handlers ...Handler) *IRoutes {
	return e.newNameAPI(name, "GET", relativePath, handlers...)
}

// 根据输入的方法RESTFull方法名 "HEAD" 创建HEAD方法
func (e *Engine) newNameHEAD(name,relativePath string, handlers ...Handler) *IRoutes {
	return e.newNameAPI(name, "HEAD", relativePath, handlers...)
}

// 根据输入的方法RESTFull方法名 "OPTIONS" 创建OPTIONS方法
func (e *Engine) newNameOPTIONS(name,relativePath string, handlers ...Handler) *IRoutes {
	return e.newNameAPI(name, "OPTIONS", relativePath, handlers...)
}

// 根据输入的方法RESTFull方法名 "POST" 创建POST方法
func (e *Engine) newNamePOST(name,relativePath string, handlers ...Handler) *IRoutes {
	return e.newNameAPI(name, "POST", relativePath, handlers...)
}

// 根据输入的方法RESTFull方法名 "PUT" 创建PUT方法
func (e *Engine) newNamePUT(name,relativePath string, handlers ...Handler) *IRoutes {
	return e.newNameAPI(name, "PUT", relativePath, handlers...)
}

// 根据输入的方法RESTFull方法名 "PATCH" 创建PATCH方法
func (e *Engine) newNamePATCH(name,relativePath string, handlers ...Handler) *IRoutes {
	return e.newNameAPI(name, "PATCH", relativePath, handlers...)
}

// 根据输入的方法RESTFull方法名 "DELETE" 创建DELETE方法
func (e *Engine) newNameDELETE(name,relativePath string, handlers ...Handler) *IRoutes {
	return e.newNameAPI(name, "DELETE", relativePath, handlers...)
}
//*******************************************************

// 使用名称创建一个隔离的静态muxAPI节点。
func (e *Engine) Static(name, relativePath string, root string, nocompressAndNocache ...bool) *IRoutes {
	return (&IRoutes{engine: e}).nameStatic(name, relativePath, root, nocompressAndNocache...)
}

// 使用名称创建一个隔离的静态muxAPI节点。
func (e *Engine) StaticFS(name, relativePath string, fs FileSystem) *IRoutes {
	return (&IRoutes{engine: e}).nameStaticFS(name, relativePath, fs)
}

func (e *Engine) presetSystemMuxes() {
	var hadUpload, hadStatic bool
	for _, child := range e.IRoutes.children {
		if strings.Contains(child.relativePath, "/upload/") {
			hadUpload = true
		}
		if strings.Contains(child.relativePath, "/static/") {
			hadStatic = true
		}
	}
	// When does not have a custom route, the route is automatically created.
	if !hadUpload && e.config.Router.DefaultUpload {
		e.IRoutes.nameStatic(
			"Directory for uploading files",
			"/upload/",
			global.upload.root,
			global.upload.nocompress,
			global.upload.nocache,
		).Use(global.upload.handlers...)
	}
	if !hadStatic && e.config.Router.DefaultStatic {
		e.IRoutes.nameStatic(
			"Directory for public static files",
			"/static/",
			global.static.root,
			global.static.nocompress,
			global.static.nocache,
		).Use(global.static.handlers...)
	}
}

func (e *Engine) registerSession() {
	if !e.config.Session.Enable {
		return
	}
	conf := &session.ManagerConfig{
		CookieName:              e.config.Session.Name,
		EnableSetCookie:         e.config.Session.AutoSetCookie,
		CookieLifeTime:          e.config.Session.CookieLifeSecond,
		Gclifetime:              e.config.Session.GcLifeSecond,
		Maxlifetime:             e.config.Session.MaxLifeSecond,
		Secure:                  true,
		ProviderConfig:          e.config.Session.ProviderConfig,
		Domain:                  e.config.Session.Domain,
		EnableSidInHttpHeader:   e.config.Session.EnableSidInHttpHeader,
		SessionNameInHttpHeader: e.config.Session.NameInHttpHeader,
		EnableSidInUrlQuery:     e.config.Session.EnableSidInUrlQuery,
	}
	var err error
	e.sessionManager, err = session.NewManager(e.config.Session.Provider, conf)
	if err != nil {
		panic(err)
	}
	go e.sessionManager.GC()
}

// ServeHTTP makes the router implement the http.Handler interface.
func (e *Engine) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var start = time.Now()
	var ctx = e.getContext(w, req)
	defer func() {
		if rcv := recover(); rcv != nil {
			panicHandler(ctx, rcv)
		}
		e.putContext(ctx)
	}()
	var method = ctx.Method()
	var u = ctx.URI()
	if u == "" {
		u = "/"
	}

	e.serveHTTP(ctx)
	var n = ctx.Status()
	var code string
	switch {
	case n >= 500:
		code = color.Red(n)
	case n >= 400:
		code = color.Magenta(n)
	case n >= 300:
		code = color.Grey(n)
	default:
		code = color.Green(n)
	}
	cost := time.Since(start)
	if cost < e.config.slowResponseThreshold {
		e.syslog.Infof("[I] %15s %7s  %3s %10d %12s %-30s | %s", ctx.RealIP(), method, code, ctx.Size(), cost, u, ctx.recordBody())
	} else {
		e.syslog.Warningf(color.Yellow("[W]")+" %15s %7s  %3s %10d %12s(slow) %-30s | %s", ctx.RealIP(), method, code, ctx.Size(), cost, u, ctx.recordBody())
	}
}

func (e *Engine) serveHTTP(ctx *Context) {
	if e.httpRedirectHttps && !ctx.IsSecure() {
		u := ctx.URL()
		u.Scheme = "https"
		u.Host = ctx.Domain() + ":" + e.httpsPort
		http.Redirect(ctx.W, ctx.R, u.String(), 307)
		return
	}
	if !ctx.doFilter() {
		return
	}
	var path = ctx.Path()
	var method = ctx.Method()
	// find dynamic resource or default static resource
	if e.tryHandle(ctx, path, method, e.dynamicSrcTree) {
		return
	}
	// find custom static resource
	if e.tryHandle(ctx, path, method, e.staticSrcTree) {
		return
	}
	// Handle 404
	global.errorFunc(ctx, "Not Found", 404)
}

func (e *Engine) tryHandle(ctx *Context, path, method string, tree map[string]*node) bool {
	if root := tree[method]; root != nil {
		if handle, ps, tsr := root.getValue(path); handle != nil {
			handle(ctx, ps)
			return true
		} else if method != "CONNECT" && path != "/" {
			code := 301 // Permanent redirect, request with GET method
			if method != "GET" {
				// Temporary redirect, request with same method
				// As of Go 1.3, Go does not support status code 308.
				code = 307
			}

			if tsr && e.redirectTrailingSlash {
				if len(path) > 1 && path[len(path)-1] == '/' {
					ctx.ModifyPath(path[:len(path)-1])
				} else {
					ctx.ModifyPath(path + "/")
				}
				http.Redirect(ctx.W, ctx.R, ctx.URL().String(), code)
				return true
			}

			// Try to fix the request path
			if e.redirectFixedPath {
				fixedPath, found := root.findCaseInsensitivePath(
					CleanToURL(path),
					e.redirectTrailingSlash,
				)
				if found {
					ctx.ModifyPath(BytesToString(fixedPath))
					http.Redirect(ctx.W, ctx.R, ctx.URL().String(), code)
					return true
				}
			}
		}
	}

	if method == "OPTIONS" {
		// Handle OPTIONS requests
		if e.handleOPTIONS {
			if allow := e.allowed(path, method); len(allow) > 0 {
				ctx.SetHeader("Allow", allow)
				ctx.W.WriteHeader(204)
				return true
			}
		}
	} else {
		// Handle 405
		if e.handleMethodNotAllowed {
			if allow := e.allowed(path, method); len(allow) > 0 {
				ctx.SetHeader("Allow", allow)
				global.errorFunc(ctx, "Method Not Allowed", 405)
				return true
			}
		}
	}
	return false
}

func (e *Engine) allowed(path, reqMethod string) (allow string) {
	if path == "*" { // server-wide
		for method := range e.dynamicSrcTree {
			if method == "OPTIONS" {
				continue
			}

			// add request method to list of allowed methods
			if len(allow) == 0 {
				allow = method
			} else {
				allow += ", " + method
			}
		}
	} else { // specific path
		for method := range e.dynamicSrcTree {
			// Skip the requested method - we already tried this one
			if method == reqMethod || method == "OPTIONS" {
				continue
			}

			handle, _, _ := e.dynamicSrcTree[method].getValue(path)
			if handle != nil {
				// add request method to list of allowed methods
				if len(allow) == 0 {
					allow = method
				} else {
					allow += ", " + method
				}
			}
		}
	}
	if len(allow) > 0 {
		allow += ", OPTIONS"
	}
	return
}

// makeHandle makes an *apiware.ParamsAPI implements the Handle interface.
func (e *Engine) makeHandle(handlerChain HandlerChain) Handle {
	return func(ctx *Context, pathParams PathParams) {
		ctx.doHandler(handlerChain, pathParams)
	}
}

func panicHandler(ctx *Context, rcv interface{}) {
	s := []byte("/src/runtime/panic.go")
	e := []byte("\ngoroutine ")
	line := []byte("\n")
	stack := make([]byte, 4<<10) //4KB
	length := runtime.Stack(stack, true)
	start := bytes.Index(stack, s)
	stack = stack[start:length]
	start = bytes.Index(stack, line) + 1
	stack = stack[start:]
	end := bytes.LastIndex(stack, line)
	if end != -1 {
		stack = stack[:end]
	}
	end = bytes.Index(stack, e)
	if end != -1 {
		stack = stack[:end]
	}
	stack = bytes.TrimRight(stack, "\n")
	global.errorFunc(ctx, fmt.Sprintf("%v\n[TRACE]\n%s\n", rcv, stack), http.StatusInternalServerError)
}
