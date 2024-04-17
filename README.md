
# Sqyrrl - an HTTP server for files hosted in iRODS

<img src="sqyrrl.jpg" alt="Sqyrrl" width="200"/>

Sqyrrl is an HTTP server which contains an embedded iRODS client and is able to
serve data directly from iRODS.

## Installation

Sqyrrl is a available as and `amd64` binary for Linux, macOS and Windows,
or as a Docker image. Copy the file to the desired location and run it.

## Limitations

Sqyrrl is an early development version and has the following limitations:

- Does not authenticate users to the HTTP endpoint; anyone can access the data it serves.
- Only serves files that have public access in iRODS.

## Running Sqyrrl

Sqrrl authenticates to iRODS using the standard method for an iRODS client i.e.
using the iRODS environment file. It respects the `IRODS_ENVIRONMENT_FILE` environment
variable, and if that is not set, it will look for the file in the standard location
`$HOME/.irods/irods_environment.json`. Alternatively, command line option `--irods-env`
may be used to set the environment file location explicitly.

Since Sqyrrl will serve any data that it can access, it's important to use an iRODS user
with appropriate authorization. The chosen iRODS user should have access only to public
(unrestricted) data.

To start the server, use the following command:

```sh
Usage:
  sqyrrl start [flags]

Flags:
      --cert-file string   Path to the SSL certificate file
  -h, --help               help for start
      --host string        Address on which to listen, host part (default "localhost")
      --irods-env string   Path to the iRODS environment file (default "~/.irods/irods_environment.json")
      --key-file string    Path to the SSL private key file
      --port int           Port on which to listen (default 3333)

Global Flags:
      --log-level string   Set the log level (trace, debug, info, warn, error) (default "info")
```

To stop the server, send `SIGINT` or `SIGTERM` to the process. The server will wait for
active connections to close before shutting down.

For additional options, use the `--help` flag.

## iRODS authentication

Sqyrrl uses the standard iRODS environment file to authenticate to iRODS. If the user has been
authenticated with `iinit` before starting Sqyrrl, the server will use the existing iRODS auth
file created by `iinit`. If the user has not been authenticated, Sqyrrl will require the iRODS
password to be supplied using the environment variable `IRODS_PASSWORD`. Sqyrrl will then create
the iRODS auth file itself, without requiring `iinit` to be used.

## Running in a container

When running Sqyrrl in a Docker container, configuration files (iRODS environment file, SSL
certificates) should be mounted into the container and the password should be supplied using
the environment variable `IRODS_PASSWORD`.

The docker-compose.yml file in the repository contains an example configuration for running
Sqyrrl in a container.

## Dependencies

Sqyrrl uses [go-irodsclient](https://github.com/cyverse/go-irodsclient) to connect to iRODS. 

