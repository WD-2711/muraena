package session

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/evilsocket/islazy/log"
	"github.com/evilsocket/islazy/tui"

	"github.com/muraenateam/muraena/core"
)

type moduleList []Module

// Session structure
type Session struct {
	Options core.Options
	Config  *Configuration
	Modules moduleList
}

// New session
// 返回值为 *Session 指针 + error
func New() (*Session, error) {
	// opt 代表各个命令行选项的值
	opts, err := core.ParseOptions()
	if err != nil {
		return nil, err
	}

	// 配置终端输出样式
	if *opts.NoColors || !tui.Effects() {
		tui.Disable()
		log.NoEffects = true
	}

	s := &Session{
		Options: opts,
		// 长度为 0 的 Module 类型切片
		Modules: make([]Module, 0),
	}

	// 如果定义了 -version 选项，那么输出 version 并退出
	version := fmt.Sprintf("%s v%s (built for %s %s with %s)", core.Name, core.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	if *s.Options.Version {
		fmt.Println(version)
		os.Exit(0)
	}

	log.Level = log.INFO
	log.Format = "{datetime} {level:color}{level:name}{reset}: {message}"
	if *s.Options.Debug == true {
		// 只输出 log.Debug 级别的消息
		log.Level = log.DEBUG
		log.Debug("DEBUG ON")
	}

	// 输出 banner 与 version
	log.Format = "\n{message}{reset}"
	log.Important(tui.Bold(tui.Red(string(core.Banner))), version)

	log.Format = "{datetime} {level:color}{level:name}{reset}: {message}"

	// 加载 configuration
	if err := s.GetConfiguration(); err != nil {
		return nil, err
	}

	// 加载 Redis
	if err = s.InitRedis(); err != nil {
		log.Fatal("%s", err)
	}

	log.Info("Connected to Redis")

	// 开启一个协程
	// 加载 prompt
	// 命令行应用程序的交互式提示
	go Prompt(s)

	return s, nil
}

// 从 session 中取回 module
func (s *Session) Module(name string) (mod Module, err error) {
	for _, m := range s.Modules {
		if m.Name() == name {
			return m, nil
		}
	}

	return nil, fmt.Errorf("module %s not found", name)
}

// Register 将模块添加到 session 中
func (s *Session) Register(mod Module, err error) {
	if err != nil {
		log.Error(err.Error())
	} else {
		s.Modules = append(s.Modules, mod)
	}
}

// GetModuleNames 返回可用 modules 的列表
func (s *Session) GetModuleNames() (mods []string) {

	for _, m := range s.Modules {
		mods = append(mods, strings.ToLower(m.Name()))
	}

	return mods
}
