# modware-auth

[![License](https://img.shields.io/badge/License-BSD%202--Clause-blue.svg)](LICENSE)  
![GitHub action](https://github.com/dictyBase/modware-auth/workflows/Test%20coverage/badge.svg)
[![codecov](https://codecov.io/gh/dictyBase/modware-auth/branch/develop/graph/badge.svg)](https://codecov.io/gh/dictyBase/modware-auth)  
[![Technical debt](https://badgen.net/codeclimate/tech-debt/dictyBase/modware-auth)](https://codeclimate.com/github/dictyBase/modware-auth/trends/technical_debt)
[![Issues](https://badgen.net/codeclimate/issues/dictyBase/modware-auth)](https://codeclimate.com/github/dictyBase/modware-auth/issues)
[![Maintainability](https://api.codeclimate.com/v1/badges/21ed283a6186cfa3d003/maintainability)](https://codeclimate.com/github/dictyBase/modware-auth/maintainability)
[![Dependabot Status](https://api.dependabot.com/badges/status?host=github&repo=dictyBase/modware-auth)](https://dependabot.com)  
![Issues](https://badgen.net/github/issues/dictyBase/modware-auth)
![Open Issues](https://badgen.net/github/open-issues/dictyBase/modware-auth)
![Closed Issues](https://badgen.net/github/closed-issues/dictyBase/modware-auth)  
![Total PRS](https://badgen.net/github/prs/dictyBase/modware-auth)
![Open PRS](https://badgen.net/github/open-prs/dictyBase/modware-auth)
![Closed PRS](https://badgen.net/github/closed-prs/dictyBase/modware-auth)
![Merged PRS](https://badgen.net/github/merged-prs/dictyBase/modware-auth)  
![Commits](https://badgen.net/github/commits/dictyBase/modware-auth/develop)
![Last commit](https://badgen.net/github/last-commit/dictyBase/modware-auth/develop)
![Branches](https://badgen.net/github/branches/dictyBase/modware-auth)
![Tags](https://badgen.net/github/tags/dictyBase/modware-auth/?color=cyan)  
![GitHub repo size](https://img.shields.io/github/repo-size/dictyBase/modware-auth?style=plastic)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/dictyBase/modware-auth?style=plastic)
[![Lines of Code](https://badgen.net/codeclimate/loc/dictyBase/modware-auth)](https://codeclimate.com/github/dictyBase/modware-auth/code)  
[![Funding](https://badgen.net/badge/NIGMS/Rex%20L%20Chisholm,dictyBase/yellow?list=|)](https://projectreporter.nih.gov/project_info_description.cfm?aid=9476993)
[![Funding](https://badgen.net/badge/NIGMS/Rex%20L%20Chisholm,DSC/yellow?list=|)](https://projectreporter.nih.gov/project_info_description.cfm?aid=9438930)

dictyBase gRPC service for authorization server, generating and validating JWTs

## Usage

```
NAME:
   modware-auth - cli for modware-auth microservice

USAGE:
   app [global options] command [command options] [arguments...]

VERSION:
   1.0.0

COMMANDS:
   start-server   starts the modware-auth microservice with grpc backend
   generate-keys  generate rsa key pairs (public and private keys) in pem format
   help, h        Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --log-format value  format of the logging out, either of json or text. (default: "json")
   --log-level value   log level for the application (default: "error")
   --help, -h          show help
   --version, -v       print the version
```

## Subcommands

```
NAME:
   app start-server - starts the modware-auth microservice with grpc backend

USAGE:
   app start-server [command options] [arguments...]

OPTIONS:
   --config value, -c value            config file (required) [$OAUTH_CONFIG]
   --pkey value, --public-key value    public key file for verifying jwt [$JWT_PUBLIC_KEY]
   --private-key value, --prkey value  private key file for signing jwt [$JWT_PRIVATE_KEY]
   --user-grpc-host value              user grpc host [$USER_API_SERVICE_HOST]
   --user-grpc-port value              user grpc port [$USER_API_SERVICE_PORT]
   --identity-grpc-host value          identity grpc host [$IDENTITY_API_SERVICE_HOST]
   --identity-grpc-port value          identity grpc port [$IDENTITY_API_SERVICE_PORT]
   --redis-master-service-host value   redis master grpc host [$REDIS_MASTER_SERVICE_HOST]
   --redis-master-service-port value   redis master grpc port [$REDIS_MASTER_SERVICE_PORT]
   --port value                        tcp port at which the server will be available (default: "9560")
   --nats-host value                   nats messaging server host [$NATS_SERVICE_HOST]
   --nats-port value                   nats messaging server port [$NATS_SERVICE_PORT]
```

```
NAME:
   app generate-keys - generate rsa key pairs (public and private keys) in pem format

USAGE:
   app generate-keys [command options] [arguments...]

OPTIONS:
   --private value, --pr value  output file name for private key
   --public value, --pub value  output file name for public key
```

# API

### gRPC

The Protocol Buffer definitions and service APIs are documented
[here](https://github.com/dictyBase/dictybaseapis/blob/master/dictybase/auth/auth.proto).

# Active Developers

<a href="https://sourcerer.io/cybersiddhu"><img src="https://sourcerer.io/assets/avatar/cybersiddhu" height="80px" alt="Sourcerer"></a>
<a href="https://sourcerer.io/wildlifehexagon"><img src="https://sourcerer.io/assets/avatar/wildlifehexagon" height="80px" alt="Sourcerer"></a>
