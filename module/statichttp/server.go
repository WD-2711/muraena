// Package statichttp serves simple HTTP server
package statichttp

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/evilsocket/islazy/tui"

	"github.com/muraenateam/muraena/session"
)

const (
	// Name of this module
	Name = "static.http"

	// Description of this module
	Description = "Exposes a simple HTTP server to serve static resources during the MiTM session"

	// Author of this module
	Author = "Muraena Team"
)

// StaticHTTP module
type StaticHTTP struct {
	session.SessionModule

	Enabled       bool
	mux           *http.ServeMux
	address       string
	listeningPort int
	Protocol      string
	ListeningHost string
	LocalPath     string
	URLPath       string
}

// Name returns the module name
func (module *StaticHTTP) Name() string {
	return Name
}

// Description returns the module description
func (module *StaticHTTP) Description() string {
	return Description
}

// Author returns the module author
func (module *StaticHTTP) Author() string {
	return Author
}

// Prompt prints module status based on the provided parameters
func (module *StaticHTTP) Prompt() {
	module.Raw("No options are available for this module")
}

func Load(s *session.Session) (m *StaticHTTP, err error) {

	m = &StaticHTTP{
		SessionModule: session.NewSessionModule(Name, s),
		Enabled:       s.Config.StaticServer.Enabled,
	}

	if !m.Enabled {
		m.Debug("is disabled")
		return
	}

	config := s.Config.StaticServer
	m.Protocol = "http://"
	m.ListeningHost = "localhost"
	m.listeningPort = config.Port
	m.LocalPath = config.LocalPath
	m.URLPath = config.URLPath

	// 启用 static server 模块
	if err = m.Start(); err != nil {
		m.Debug("Dying")
		return
	}

	m.Info("I'm alive and kicking at %s", tui.Bold(tui.Green(m.address)))
	return
}

func (module *StaticHTTP) configure() error {

	module.address = fmt.Sprintf("127.0.0.1:%d", module.listeningPort)
	// ServeMux 可以用来注册和分发 HTTP 请求到相应的处理程序（handlers）。它充当了一个路由器的角色，根据 URL 路径将请求导向不同的处理程序
	module.mux = http.NewServeMux()

	path := http.Dir(module.LocalPath)
	module.Debug("[Static Server] Requested resource: %s", path)
	fileServer := http.FileServer(FileSystem{path})
	// 若访问 module.URLPath，则重定向到 module.LocalPath
	module.mux.Handle(module.URLPath, http.StripPrefix(strings.TrimRight(module.URLPath, "/"), fileServer))

	return nil
}

// Start 运行静态 HTTP 服务器模块
func (module *StaticHTTP) Start() (err error) {

	if err := module.configure(); err != nil {
		return err
	}
	// 开启协程，监听访问
	go http.ListenAndServe(module.address, module.mux)

	return nil
}

// FileSystem 自定义文件系统处理程序
type FileSystem struct {
	fs http.FileSystem
}

// Open opens file
func (fs FileSystem) Open(path string) (http.File, error) {
	f, err := fs.fs.Open(path)
	if err != nil {
		return nil, err
	}

	s, err := f.Stat()
	if s.IsDir() {
		index := strings.TrimSuffix(path, "/") + "/index.html"
		if _, err := fs.fs.Open(index); err != nil {
			return nil, err
		}
	}

	return f, nil
}

func (module *StaticHTTP) MakeDestinationURL(URL *url.URL) (destination string) {

	destination = ""
	if strings.HasPrefix(URL.Path, module.URLPath) {
		destination = fmt.Sprintf("%s%s:%d", module.Protocol, module.ListeningHost, module.listeningPort)
	}

	return
}
