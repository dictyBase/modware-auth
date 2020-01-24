package nats

import (
	"context"
	"fmt"
	"time"

	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
	"github.com/dictyBase/go-genproto/dictybaseapis/pubsub"
	"github.com/dictyBase/modware-auth/internal/message"
	gnats "github.com/nats-io/go-nats"
	"github.com/nats-io/go-nats/encoders/protobuf"
)

type natsMessaging struct {
	econn *gnats.EncodedConn
}

func NewMessaging(host, port string, options ...gnats.Option) (message.Messaging, error) {
	nc, err := gnats.Connect(fmt.Sprintf("nats://%s:%s", host, port), options...)
	if err != nil {
		return &natsMessaging{}, err
	}
	ec, err := gnats.NewEncodedConn(nc, protobuf.PROTOBUF_ENCODER)
	if err != nil {
		return &natsMessaging{}, err
	}
	return &natsMessaging{econn: ec}, nil
}

func (n *natsMessaging) PublishTokens(subj string, t *auth.Token) error {
	return n.econn.Publish(subj, t)
}

func (n *natsMessaging) Close() error {
	n.econn.Close()
	return nil
}

func (n *natsMessaging) UserRequest(subj string, r *pubsub.IdRequest, timeout time.Duration) (*pubsub.UserReply, error) {
	reply := &pubsub.UserReply{}
	err := n.econn.Request(subj, r, reply, timeout)
	return reply, err
}

func (n *natsMessaging) UserRequestWithContext(ctx context.Context, subj string, r *pubsub.IdRequest) (*pubsub.UserReply, error) {
	reply := &pubsub.UserReply{}
	err := n.econn.RequestWithContext(ctx, subj, r, reply)
	return reply, err
}

func (n *natsMessaging) IdentityRequest(subj string, r *pubsub.IdentityReq, timeout time.Duration) (*pubsub.IdentityReply, error) {
	reply := &pubsub.IdentityReply{}
	err := n.econn.Request(subj, r, reply, timeout)
	return reply, err
}

func (n *natsMessaging) IdentityRequestWithContext(ctx context.Context, subj string, r *pubsub.IdentityReq) (*pubsub.IdentityReply, error) {
	reply := &pubsub.IdentityReply{}
	err := n.econn.RequestWithContext(ctx, subj, r, reply)
	return reply, err
}
