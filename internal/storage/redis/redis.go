package redis

import (
	"github.com/dictyBase/modware-auth/internal/storage"
	r "github.com/go-redis/redis"
)

type RedisStorage struct {
	master *r.Client
	slave  *r.Client
}

func NewRedisStorage(master, slave string) storage.Storage {
	return &RedisStorage{
		master: r.NewClient(&r.Options{Addr: master}),
		slave:  r.NewClient(&r.Options{Addr: slave}),
	}
}

func (rs *RedisStorage) Close() error {
	if err := rs.master.Close(); err != nil {
		return err
	}
	if err := rs.slave.Close(); err != nil {
		return err
	}
	return nil
}

func (rs *RedisStorage) Get(key, field string) (string, error) {
	return rs.slave.HGet(key, field).Result()
}

func (rs *RedisStorage) Set(key, field, val string) error {
	return rs.master.HSet(key, field, val).Err()
}

func (rs *RedisStorage) Delete(key string, fields ...string) error {
	return rs.master.HDel(key, fields...).Err()
}

func (rs *RedisStorage) IsExist(key, field string) bool {
	b, err := rs.slave.HExists(key, field).Result()
	if err != nil {
		return false
	}
	return b
}
