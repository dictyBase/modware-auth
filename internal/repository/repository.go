package repository

import "time"

type AuthRepository interface {
	GetToken(string) ([]byte, error)
	AddToken(string, []byte, time.Duration) error
	RemoveToken(string) error
}
