package crawler

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	// 代码美化工具
	"github.com/ditashi/jsbeautifier-go/jsbeautifier"
	"github.com/evilsocket/islazy/tui"

	// 抓取框架
	"github.com/gocolly/colly/v2"
	"github.com/icza/abcsort"

	// 简单 HTTP 客户端库
	"gopkg.in/resty.v1"
	"mvdan.cc/xurls/v2"

	"github.com/muraenateam/muraena/core/proxy"
	"github.com/muraenateam/muraena/session"
)

const (
	// Name of this module
	Name = "crawler"

	// Description of this module
	Description = "Crawls the target domain in order to retrieve most of the target external origins"

	// Author of this module
	Author = "Muraena Team"
)

// Crawler module
type Crawler struct {
	session.SessionModule

	Enabled bool
	Depth   int
	UpTo    int

	Domains []string
}

var (
	discoveredJsUrls []string
	waitGroup        sync.WaitGroup
	rgxURLS          *regexp.Regexp
)

// Name returns the module name
func (module *Crawler) Name() string {
	return Name
}

// Description returns the module description
func (module *Crawler) Description() string {
	return Description
}

// Author returns the module author
func (module *Crawler) Author() string {
	return Author
}

// Prompt prints module status based on the provided parameters
func (module *Crawler) Prompt() {
	module.Raw("No options are available for this module")
}

// Load 通过初始化模块的主要结构和变量来配置模块
// 返回值为 (m *Crawler, err error)
func Load(s *session.Session) (m *Crawler, err error) {

	config := s.Config.Crawler
	m = &Crawler{
		SessionModule: session.NewSessionModule(Name, s),
		Enabled:       config.Enabled,
		UpTo:          config.UpTo,
		Depth:         config.Depth,
	}
	// xurls 是一个用于提取 URL 的正则表达式工具库
	rgxURLS = xurls.Strict()

	// ExternalOrigins 去重
	config.ExternalOrigins = proxy.ArmorDomain(config.ExternalOrigins)
	if !m.Enabled {
		m.Debug("is disabled")
		return
	}
	// 进行爬取
	m.explore()
	// 简化 domain
	m.SimplifyDomains()
	config.ExternalOrigins = m.Domains

	m.Info("Domain crawling stats:")
	err = s.UpdateConfiguration(&m.Domains)

	return
}

func (module *Crawler) explore() {
	// 等待 waitGroup == 0
	waitGroup.Wait()

	// Custom client
	// 创建一个自定义的 HTTP 客户端 collyClient，可以使用该客户端来发送 HTTP 请求
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	collyClient := &http.Client{Transport: tr}

	// 定义 colly 抓取框架实例化后的对象 c
	c := colly.NewCollector(
		colly.UserAgent("Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"),
		// MaxDepth 默认为 1，因此仅访问已抓取页面上的链接，不会再访问其他链接
		colly.MaxDepth(module.Depth),
		colly.CheckHead(),
	)

	c.SetClient(collyClient)

	numVisited := 0
	// 当 Collector 发出请求时自动执行此函数
	c.OnRequest(func(r *colly.Request) {
		numVisited++
		// 当请求次数大于 module.UpTo 时取消 http 请求
		if numVisited > module.UpTo {
			r.Abort()
			return
		}
	})
	// 对 <script> 标签的 src 属性进行处理
	c.OnHTML("script[src]", func(e *colly.HTMLElement) {
		// res 是 <script> 标签的 src 属性
		res := e.Attr("src")
		if module.appendExternalDomain(res) {
			// 如果它是来自 external domain 的脚本，请确保获取它
			// 访问 js 中的 url，并从返回值中继续获取 url，添加到 external domain 中
			waitGroup.Add(1)
			go module.fetchJS(&waitGroup, res)
		}

	})

	// 其他有 src 属性的 tags (img/video/iframe/etc..)
	c.OnHTML("[src]", func(e *colly.HTMLElement) {
		res := e.Attr("src")
		module.appendExternalDomain(res)
	})
	// 用于引入外部资源，例如 CSS 文件
	c.OnHTML("link[href]", func(e *colly.HTMLElement) {
		res := e.Attr("href")
		module.appendExternalDomain(res)
	})

	c.OnHTML("meta[content]", func(e *colly.HTMLElement) {
		res := e.Attr("content")
		module.appendExternalDomain(res)
	})

	// 超链接元素
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		res := e.Attr("href")
		module.appendExternalDomain(res)
	})
	// 定义爬虫规则，表示对所有域名都应用"每次爬取页面间会随机延迟0-500ms"的规则
	if err := c.Limit(&colly.LimitRule{DomainGlob: "*", RandomDelay: 500 * time.Millisecond}); err != nil {
		module.Warning("[Colly Limit]%s", err)
	}

	c.OnResponse(func(r *colly.Response) {})

	c.OnRequest(func(r *colly.Request) {})

	var config *session.Configuration
	config = module.Session.Config

	module.Info("Starting exploration of %s (crawlDepth:%d crawlMaxReq: %d), just a few seconds...", config.Proxy.Target, module.Depth, module.UpTo)

	dest := fmt.Sprintf("%s%s", config.Protocol, config.Proxy.Target)
	// 爬取 dest ？？？
	err := c.Visit(dest)
	if err != nil {
		module.Info("Exploration error visiting %s: %s", dest, tui.Red(err.Error()))
	}
}

func (module *Crawler) fetchJS(waitGroup *sync.WaitGroup, res string) {

	// 此函数返回前调用 waitGroup.Done()
	defer waitGroup.Done()

	u, _ := url.Parse(res)
	if u.Scheme == "" {
		u.Scheme = "https://"
		res = "https:" + res
	}
	nu := fmt.Sprintf("%s%s", u.Host, u.Path)
	if !Contains(&discoveredJsUrls, nu) {
		discoveredJsUrls = append(discoveredJsUrls, nu)
		module.Debug("New JS: %s", nu)
		// get 方式请求 res
		resp, err := resty.R().Get(res)
		if err != nil {
			module.Error("Error fetching JS at %s: %s", res, err)
			return
		}

		body := string(resp.Body())
		opts := jsbeautifier.DefaultOptions()
		// 美化返回的 body
		beautyBody, err := jsbeautifier.Beautify(&body, opts)
		if err != nil {
			module.Error("Error beautifying JS at %s", res)
			return
		}
		// 在 beautyBody 中找到所有的 url
		jsUrls := rgxURLS.FindAllString(beautyBody, -1)
		if len(jsUrls) > 0 && len(jsUrls) < 100 {
			for _, jsURL := range jsUrls {
				module.appendExternalDomain(jsURL)
			}
			module.Info("%d domain(s) found in JS at %s", len(jsUrls), res)
		}
	}
}

// 判断是否来自 Externa lDomain
func (module *Crawler) appendExternalDomain(res string) bool {
	if strings.HasPrefix(res, "//") || strings.HasPrefix(res, "https://") || strings.HasPrefix(res, "http://") {
		u, err := url.Parse(res)
		if err != nil {
			module.Error("url.Parse error, skipping external domain %s: %s", res, err)
			return false
		}
		// http://example.com/path/to/resource
		// u.Scheme: http
		// u.Host: example.com
		// u.Path: /path/to/resource
		// 在从 JS 文件解析 url 时，进行一些检查后更新域
		if len(u.Host) > 2 && (strings.Contains(u.Host, ".") || strings.Contains(u.Host, ":")) {
			module.Domains = append(module.Domains, u.Host)
		}

		return true
	}

	return false
}

// 将 []string 切片倒序
func reverseString(ss []string) []string {
	last := len(ss) - 1
	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}

	return ss
}

// SimplifyDomains 通过将第 3 级和第 4 级子域分组为 *.<domain> 来简化域切片
func (module *Crawler) SimplifyDomains() {

	var domains []string
	for _, d := range module.Domains {

		host := strings.TrimSpace(d)
		hostParts := reverseString(strings.Split(host, "."))

		switch len(hostParts) {
		case 3:
			host = fmt.Sprintf("*.%s.%s", hostParts[1], hostParts[0])
		case 4:
			host = fmt.Sprintf("*.%s.%s.%s", hostParts[2], hostParts[1], hostParts[0])

		default:
			// Don't do anything, more than 3rd level is too much
		}

		domains = append(domains, host)
	}

	sorter := abcsort.New("*")
	domains = proxy.ArmorDomain(domains)
	sorter.Strings(domains)

	module.Domains = domains
}
