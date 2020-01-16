package storage

type Storage interface {
	Get(string, string) (string, error)
	Set(string, string, string) error
	Delete(string, ...string) error
	IsExist(string, string) bool
	Close() error
}
