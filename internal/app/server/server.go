package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/dictyBase/modware-auth/internal/jwtauth"

	"github.com/dictyBase/aphgrpc"
	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
	"github.com/dictyBase/go-genproto/dictybaseapis/identity"
	"github.com/dictyBase/go-genproto/dictybaseapis/user"
	"github.com/dictyBase/modware-auth/internal/app/service"
	"github.com/dictyBase/modware-auth/internal/message"
	"github.com/dictyBase/modware-auth/internal/message/nats"
	"github.com/dictyBase/modware-auth/internal/oauth"
	"github.com/dictyBase/modware-auth/internal/repository"
	"github.com/dictyBase/modware-auth/internal/repository/redis"
	"github.com/golang-jwt/jwt"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	gnats "github.com/nats-io/go-nats"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type ClientsGRPC struct {
	userClient     user.UserServiceClient
	identityClient identity.IdentityServiceClient
}

type Connections struct {
	authRepo  repository.AuthRepository
	publisher message.Publisher
}

func RunServer(c *cli.Context) error {
	conns, err := getConnections(c)
	if err != nil {
		return cli.NewExitError(
			fmt.Sprintf("Unable to connect to external service %q", err),
			2,
		)
	}
	clients, err := connectToGRPC(c)
	if err != nil {
		return cli.NewExitError(
			fmt.Sprintf("Unable to connect to grpc client %q", err),
			2,
		)
	}
	config, err := readSecretConfig(c)
	if err != nil {
		return cli.NewExitError(
			fmt.Sprintf("Unable to read secret config file %q", err),
			2,
		)
	}
	jt, err := parseJwtKeys(c)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Unable to parse keys %q", err), 2)
	}
	grpcS := grpc.NewServer(
		grpc_middleware.WithUnaryServerChain(
			grpc_ctxtags.UnaryServerInterceptor(),
			grpc_logrus.UnaryServerInterceptor(getLogger(c)),
		),
	)
	srv, err := service.NewAuthService(&service.ServiceParams{
		Repository:      conns.authRepo,
		Publisher:       conns.publisher,
		User:            clients.userClient,
		Identity:        clients.identityClient,
		JWTAuth:         *jt,
		ProviderSecrets: *config,
		Options:         getGrpcOpt(),
	},
	)
	if err != nil {
		return cli.NewExitError(err.Error(), 2)
	}
	auth.RegisterAuthServiceServer(grpcS, srv)
	reflection.Register(grpcS)
	endP := fmt.Sprintf(":%s", c.String("port"))
	lis, err := net.Listen("tcp", endP)
	if err != nil {
		return cli.NewExitError(
			fmt.Sprintf("failed to listen %s", err), 2,
		)
	}
	log.Printf("starting grpc server on %s", endP)
	if err := grpcS.Serve(lis); err != nil {
		return cli.NewExitError(err.Error(), 2)
	}
	return nil
}

// Reads the configuration file containing the various client secret keys
// of the providers. The expected format will be ...
//
//	 {
//			"google": "xxxxxxxxxxxx",
//			"orcid": "xxxxxxxx",
//		}
func readSecretConfig(c *cli.Context) (*oauth.ProviderSecrets, error) {
	var provider *oauth.ProviderSecrets
	data, err := base64.StdEncoding.DecodeString(c.String("config"))
	if err != nil {
		return provider, err
	}
	if err := json.Unmarshal(data, &provider); err != nil {
		return provider, err
	}
	return provider, nil
}

// Reads the public and private keys from their respective files and
// creates a new JWTAuth instance.
func parseJwtKeys(c *cli.Context) (*jwtauth.JWTAuth, error) {
	ja := &jwtauth.JWTAuth{}
	private, err := base64.StdEncoding.DecodeString(c.String("private-key"))
	if err != nil {
		return ja, err
	}
	pkey, err := jwt.ParseRSAPrivateKeyFromPEM(private)
	if err != nil {
		return ja, err
	}
	public, err := base64.StdEncoding.DecodeString(c.String("public-key"))
	if err != nil {
		return ja, err
	}
	pubkey, err := jwt.ParseRSAPublicKeyFromPEM(public)
	if err != nil {
		return ja, err
	}
	return jwtauth.NewJwtAuth(jwt.SigningMethodRS512, pkey, pubkey), err
}

// get external connections to redis, nats
func getConnections(c *cli.Context) (*Connections, error) {
	conn := &Connections{}
	redisAddr := fmt.Sprintf(
		"%s:%s",
		c.String("redis-master-service-host"),
		c.String("redis-master-service-port"),
	)
	rrepo, err := redis.NewAuthRepo(redisAddr)
	if err != nil {
		return conn, fmt.Errorf(
			"cannot connect to redis auth repository %s",
			err,
		)
	}
	ms, err := nats.NewPublisher(
		c.String("nats-host"), c.String("nats-port"),
		gnats.MaxReconnects(-1), gnats.ReconnectWait(2*time.Second),
	)
	if err != nil {
		return conn, fmt.Errorf("cannot connect to messaging server %s", err)
	}
	conn.authRepo = rrepo
	conn.publisher = ms
	return conn, nil
}

// connect to necessary grpc clients
func connectToGRPC(c *cli.Context) (*ClientsGRPC, error) {
	clients := &ClientsGRPC{}
	userAddr := fmt.Sprintf(
		"%s:%s",
		c.String("user-grpc-host"),
		c.String("user-grpc-port"),
	)
	// establish grpc connections
	uconn, err := grpc.Dial(userAddr, grpc.WithInsecure())
	if err != nil {
		return clients, fmt.Errorf(
			"cannot connect to grpc user microservice %s",
			err,
		)
	}
	idnAddr := fmt.Sprintf(
		"%s:%s",
		c.String("identity-grpc-host"),
		c.String("identity-grpc-port"),
	)
	iconn, err := grpc.Dial(idnAddr, grpc.WithInsecure())
	if err != nil {
		return clients, fmt.Errorf(
			"cannot connect to grpc identity microservice %s",
			err,
		)
	}
	clients.userClient = user.NewUserServiceClient(uconn)
	clients.identityClient = identity.NewIdentityServiceClient(iconn)
	return clients, nil
}

// get grpc topics options
func getGrpcOpt() []aphgrpc.Option {
	return []aphgrpc.Option{
		aphgrpc.TopicsOption(map[string]string{
			"tokenCreate": "AuthService.Create",
		}),
	}
}

func getLogger(c *cli.Context) *logrus.Entry {
	log := logrus.New()
	log.Out = os.Stderr
	switch c.GlobalString("log-format") {
	case "text":
		log.Formatter = &logrus.TextFormatter{
			TimestampFormat: "02/Jan/2006:15:04:05",
		}
	case "json":
		log.Formatter = &logrus.JSONFormatter{
			TimestampFormat: "02/Jan/2006:15:04:05",
		}
	}
	l := c.GlobalString("log-level")
	switch l {
	case "debug":
		log.Level = logrus.DebugLevel
	case "warn":
		log.Level = logrus.WarnLevel
	case "error":
		log.Level = logrus.ErrorLevel
	case "fatal":
		log.Level = logrus.FatalLevel
	case "panic":
		log.Level = logrus.PanicLevel
	}
	return logrus.NewEntry(log)
}
