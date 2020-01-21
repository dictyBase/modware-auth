package repository

import "time"

type AuthRepository interface {
	GetToken(string) (string, error)
	SetToken(string, string, time.Duration) error
	DeleteToken(string) error
	HasToken(string) (bool, error)
}
