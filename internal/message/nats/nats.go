package nats

import (
	"fmt"

	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
	"github.com/dictyBase/modware-auth/internal/message"
	gnats "github.com/nats-io/go-nats"
	"github.com/nats-io/go-nats/encoders/protobuf"
)

type natsPublisher struct {
	econn *gnats.EncodedConn
}

func NewPublisher(host, port string, options ...gnats.Option) (message.Publisher, error) {
	nc, err := gnats.Connect(fmt.Sprintf("nats://%s:%s", host, port), options...)
	if err != nil {
		return &natsPublisher{}, err
	}
	ec, err := gnats.NewEncodedConn(nc, protobuf.PROTOBUF_ENCODER)
	if err != nil {
		return &natsPublisher{}, err
	}
	return &natsPublisher{econn: ec}, nil
}

func (n *natsPublisher) Publish(subj string, a *auth.Auth) error {
	return n.econn.Publish(subj, a)
}

func (n *natsPublisher) Close() error {
	n.econn.Close()
	return nil
}