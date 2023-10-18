package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/evilsocket/islazy/tui"
	"github.com/gomodule/redigo/redis"
)

var (
	host     = "127.0.0.1"
	port     = 6379
	password = ""

	RedisPool *redis.Pool
)

// InitRedis 初始化到 Redis 数据库的链接
func (s *Session) InitRedis() error {

	var config = s.Config.Redis

	if config.Host != "" {
		host = config.Host
	}

	if config.Password != "" {
		password = config.Password
	}

	if config.Port != 0 {
		port = config.Port
	}

	// 初始化新的 Redis 数据库池
	RedisPool = newRedisPool()
	// 尝试连接 Redis
	if _, err := RedisPool.Dial(); err != nil {
		return errors.New(fmt.Sprintf("%s %s", tui.Wrap(tui.BACKLIGHTBLUE, tui.Wrap(tui.FOREBLACK, "redis")), err.Error()))
	}

	return nil
}

func newRedisPool() *redis.Pool {

	return &redis.Pool{
		// 连接池中最大的空闲连接数
		MaxIdle: 3,
		// 连接在空闲状态下的超时时间
		IdleTimeout: 240 * time.Second,
		// 定义匿名函数作为连接 Redis 的回调函数，即在每次建立新连接时被调用
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
			if err != nil {
				return nil, err
			}
			if password != "" {
				if _, err := c.Do("AUTH", password); err != nil {
					c.Close()
					return nil, err
				}
			}

			return c, err
		},
		// 在每次从连接池中借用连接时被调用，并执行一个 PING 命令来验证连接的可用性
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			_, err := c.Do("PING")
			return err
		},
	}
}
