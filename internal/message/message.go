package message

import (
	"context"
	"time"

	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
	"github.com/dictyBase/go-genproto/dictybaseapis/pubsub"
)

// Messaging manages the publishing and requesting of messages
type Messaging interface {
	// PublishTokens publishes the token object using the given subject
	PublishTokens(subject string, token *auth.Token) error
	// Close closes the connection to the underlying messaging server
	Close() error
	// UserRequest sends a request for user data
	UserRequest(string, *pubsub.IdRequest, time.Duration) (*pubsub.UserReply, error)
	// UserRequestWithContext sends a request for user data with context included
	UserRequestWithContext(context.Context, string, *pubsub.IdRequest) (*pubsub.UserReply, error)
	// IdentityRequest sends a request for identity data
	IdentityRequest(string, *pubsub.IdentityReq, time.Duration) (*pubsub.IdentityReply, error)
	// IdentityRequestWithContext sends a request for identity data with context included
	IdentityRequestWithContext(context.Context, string, *pubsub.IdentityReq) (*pubsub.IdentityReply, error)
}
