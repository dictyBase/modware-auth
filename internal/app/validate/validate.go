package validate

import (
	"fmt"

	"github.com/urfave/cli"
)

// ServerArgs validates that the necessary flags are not missing
func ServerArgs(c *cli.Context) error {
	for _, p := range []string{
		"user-grpc-host",
		"user-grpc-port",
		"identity-grpc-host",
		"identity-grpc-port",
		"nats-host",
		"nats-port",
		"redis-master-service-host",
		"redis-master-service-port",
		"config",
		"pkey",
		"prkey",
	} {
		if len(c.String(p)) == 0 {
			return cli.NewExitError(
				fmt.Sprintf("argument %s is missing", p),
				2,
			)
		}
	}
	return nil
}
