# VC

## How to build

### Docker

For convenience all services are build within a docker container.

Each service has its own make target, `make docker-build-<service>` or build all of them at once `make docker-build`

### Static binary without Docker

run `make build-<service>` to build a specific service or `make build` to build all services.

linux/amd64 is consider supported, other build options may work.
