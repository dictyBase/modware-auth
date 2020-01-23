package message

import (
	"context"
	"time"

	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
	"github.com/dictyBase/go-genproto/dictybaseapis/pubsub"
)

// Publisher manages the publishing of messages
type Publisher interface {
	// PublishTokens publishes the token object using the given subject
	PublishTokens(subject string, token *auth.Token) error
	// Close closes the connection to the underlying messaging server
	Close() error
}

// Request handles requesting any messages
type Request interface {
	IsActive() bool
	UserRequest(string, *pubsub.IdRequest, time.Duration) (*pubsub.UserReply, error)
	UserRequestWithContext(context.Context, string, *pubsub.IdRequest) (*pubsub.UserReply, error)
	IdentityRequest(string, *pubsub.IdentityReq, time.Duration) (*pubsub.IdentityReply, error)
	IdentityRequestWithContext(context.Context, string, *pubsub.IdentityReq) (*pubsub.IdentityReply, error)
}
