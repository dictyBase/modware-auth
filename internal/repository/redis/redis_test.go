package redis

import (
	"fmt"
	"log"
	"os"
	"testing"

	r "github.com/go-redis/redis/v7"
	"github.com/stretchr/testify/assert"
)

var redisAddr = fmt.Sprintf(
	"%s:%s",
	os.Getenv("REDIS_MASTER_SERVICE_HOST"),
	os.Getenv("REDIS_MASTER_SERVICE_PORT"),
)

// CheckRedisEnv checks for the presence of the following
// environment variables
//
//	REDIS_MASTER_SERVICE_HOST
//	REDIS_MASTER_SERVICE_PORT
func CheckRedisEnv() error {
	envs := []string{
		"REDIS_MASTER_SERVICE_HOST",
		"REDIS_MASTER_SERVICE_PORT",
	}
	for _, e := range envs {
		if len(os.Getenv(e)) == 0 {
			return fmt.Errorf("env %s is not set", e)
		}
	}
	return nil
}

type TestRedis struct {
	client *r.Client
}

// NewTestRedisFromEnv is a constructor for TestRedis instance.
// It expects the following environmental variables to be set.
//
//	REDIS_MASTER_SERVICE_HOST
//	REDIS_MASTER_SERVICE_PORT
func NewTestRedisFromEnv() (*TestRedis, error) {
	tr := new(TestRedis)
	if err := CheckRedisEnv(); err != nil {
		return tr, err
	}
	tr.client = r.NewClient(&r.Options{
		Addr: redisAddr,
	})
	err := tr.client.Ping().Err()
	if err != nil {
		return nil, fmt.Errorf("error pinging redis %s", err)
	}
	return tr, nil
}

func TestMain(m *testing.M) {
	_, err := NewTestRedisFromEnv()
	if err != nil {
		log.Fatalf("unable to construct new TestRedisFromEnv instance %s", err)
	}
	os.Exit(m.Run())
}

func TestSetToken(t *testing.T) {
	assert := assert.New(t)
	repo, err := NewAuthRepo(redisAddr)
	assert.NoError(err, "error connecting to redis")
	err = repo.SetToken("art", "vandelay", 0)
	assert.NoError(err, "error in setting token")
}

func TestGetToken(t *testing.T) {
	assert := assert.New(t)
	repo, err := NewAuthRepo(redisAddr)
	assert.NoError(err, "error connecting to redis")
	err = repo.SetToken("art", "vandelay", 0)
	assert.NoError(err, "error in setting token")
	token, err := repo.GetToken("art")
	assert.NoError(err, "error getting token")
	assert.Equal(token, "vandelay", "should retrieve correct value")
}

func TestDeleteToken(t *testing.T) {
	assert := assert.New(t)
	repo, err := NewAuthRepo(redisAddr)
	assert.NoError(err, "error connecting to redis")
	err = repo.SetToken("art", "vandelay", 0)
	assert.NoError(err, "error in setting token")
	err = repo.DeleteToken("art")
	assert.NoError(err, "error in deleting token")
	err = repo.DeleteToken("cheever")
	assert.Error(err, "error deleting nonexistent token")
}

func TestHasToken(t *testing.T) {
	assert := assert.New(t)
	repo, err := NewAuthRepo(redisAddr)
	assert.NoError(err, "error connecting to redis")
	err = repo.SetToken("art", "vandelay", 0)
	assert.NoError(err, "error in setting token")
	lookup, err := repo.HasToken("art")
	assert.NoError(err, "error finding token")
	assert.True(lookup, "should find previously set token")
	badLookup, err := repo.HasToken("obrien-murphy")
	assert.NoError(err, "error finding token ")
	assert.False(badLookup, "should not find random token")
}
