package message

import (
	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
)

// Publisher manages publishing of message
type Publisher interface {
	// Publis publishes the auth object using the given subject
	Publish(subject string, ann *auth.Auth) error
	// Close closes the connection to the underlying messaging server
	Close() error
}
