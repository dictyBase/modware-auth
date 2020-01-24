package message

import (
	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
)

// Publisher manages the publishing of messages
type Publisher interface {
	// PublishTokens publishes the token object using the given subject
	PublishTokens(subject string, token *auth.Token) error
	// Close closes the connection to the underlying messaging server
	Close() error
}
