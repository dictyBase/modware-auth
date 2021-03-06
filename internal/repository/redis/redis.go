package redis

import (
	"fmt"
	"time"

	"github.com/dictyBase/modware-auth/internal/repository"
	r "github.com/go-redis/redis/v7"
)

type RedisStorage struct {
	client *r.Client
}

func NewAuthRepo(redisAddress string) (repository.AuthRepository, error) {
	client := r.NewClient(&r.Options{
		Addr: redisAddress,
	})

	err := client.Ping().Err()
	if err != nil {
		return nil, fmt.Errorf("error pinging redis %s", err)
	}

	return &RedisStorage{client: client}, nil
}

func (rs *RedisStorage) GetToken(key string) (string, error) {
	val, err := rs.client.Get(key).Result()
	if err != nil {
		return "", err
	}
	return val, err
}

func (rs *RedisStorage) SetToken(key, val string, time time.Duration) error {
	return rs.client.Set(key, val, time).Err()
}

func (rs *RedisStorage) DeleteToken(key string) error {
	val, err := rs.client.Del(key).Result()
	if err != nil {
		return err
	}
	if val == 0 {
		return fmt.Errorf("token does not exist")
	}
	return nil
}

func (rs *RedisStorage) HasToken(key string) (bool, error) {
	h, err := rs.client.Exists(key).Result()
	if err != nil {
		return false, err
	}
	if h == 0 {
		return false, nil
	}
	return true, nil
}
