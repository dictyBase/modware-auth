package redis

import (
	"github.com/dictyBase/modware-auth/internal/repository"
	"time"

	r "github.com/gomodule/redigo/redis"
	"github.com/dictyBase/modware-auth/repository"
)

type RedisCache struct {
	client *r.Pool
}

func NewRedisCache(addr string) repository.AuthRepository {
	c := &r.Pool{
		MaxIdle: 4,
		IdleTimeout: 180 * time.Second,
		Dial: func() (r.Conn, error) { return r.Dial("tcp", addr)}
	}
	return &RedisCache{client: c}
}

func (rc *RedisCache) GetToken(key string) ([]byte, error) {
	c := rc.client.Get()
	defer c.Close()
	return r.Bytes(c.Do("GET", key))
}

func (rc *RedisCache) AddToken(key string, val []byte, t time.Duration) error {
	c := rc.client.Get()
	defer c.Close()
	_, err := c.Do("SET", key, val, "EX", int64(t/time.Second))
	return err
}

func (rc *RedisCache) RemoveToken(key string) error {
	c := rc.client.Get()
	defer c.Close()
	_, err := c.Do("DEL", key)
	return err
}