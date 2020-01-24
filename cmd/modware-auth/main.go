package main

import (
	"log"
	"os"

	apiflag "github.com/dictyBase/aphgrpc"
	"github.com/dictyBase/modware-auth/internal/app/generate"
	"github.com/dictyBase/modware-auth/internal/app/server"
	"github.com/dictyBase/modware-auth/internal/app/validate"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "modware-auth"
	app.Usage = "cli for modware-auth microservice"
	app.Version = "1.0.0"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "log-format",
			Usage: "format of the logging out, either of json or text.",
			Value: "json",
		},
		cli.StringFlag{
			Name:  "log-level",
			Usage: "log level for the application",
			Value: "error",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:   "start-server",
			Usage:  "starts the modware-auth microservice with grpc backend",
			Action: server.RunServer,
			Before: validate.ServerArgs,
			Flags:  getServerFlags(),
		},
		{
			Name:   "generate-keys",
			Usage:  "generate rsa key pairs (public and private keys) in pem format",
			Action: generate.GenerateKeys,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "private, pr",
					Usage: "output file name for private key",
				},
				cli.StringFlag{
					Name:  "public, pub",
					Usage: "output file name for public key",
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("error in running command %s", err)
	}
}

func getServerFlags() []cli.Flag {
	var f []cli.Flag
	f = append(f, authFlags()...)
	f = append(f, grpcFlags()...)
	f = append(f, redisFlags()...)
	f = append(f, commonFlags()...)
	return append(f, apiflag.NatsFlag()...)
}

func commonFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:  "port",
			Usage: "tcp port at which the server will be available",
			Value: "9560",
		},
	}
}

func grpcFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:   "user-grpc-host",
			EnvVar: "USER_API_SERVICE_HOST",
			Usage:  "user grpc host",
		},
		cli.StringFlag{
			Name:   "user-grpc-port",
			EnvVar: "USER_API_SERVICE_PORT",
			Usage:  "user grpc port",
		},
		cli.StringFlag{
			Name:   "identity-grpc-host",
			EnvVar: "IDENTITY_API_SERVICE_HOST",
			Usage:  "identity grpc host",
		},
		cli.StringFlag{
			Name:   "identity-grpc-port",
			EnvVar: "IDENTITY_API_SERVICE_PORT",
			Usage:  "identity grpc port",
		},
	}
}

func redisFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:   "redis-master-service-host",
			EnvVar: "REDIS_MASTER_SERVICE_HOST",
			Usage:  "redis master grpc host",
		},
		cli.StringFlag{
			Name:   "redis-master-service-port",
			EnvVar: "REDIS_MASTER_SERVICE_PORT",
			Usage:  "redis master grpc port",
		},
	}
}

func authFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:   "config, c",
			Usage:  "config file (required)",
			EnvVar: "OAUTH_CONFIG",
		},
		cli.StringFlag{
			Name:   "pkey, public-key",
			Usage:  "public key file for verifying jwt",
			EnvVar: "JWT_PUBLIC_KEY",
		},
		cli.StringFlag{
			Name:   "private-key, prkey",
			Usage:  "private key file for signing jwt",
			EnvVar: "JWT_PRIVATE_KEY",
		},
	}
}
