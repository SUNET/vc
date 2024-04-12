# VC

This repository consists of the source code for the VC EU project, but also tools and make targets that's making sense for developers, please do not use for anything else.

## How to build

### Docker

For convenience all services are build within a docker container.

Each service has its own make target, `make docker-build-<service>` or build all of them at once `make docker-build`

### Static binary without Docker

run `make build-<service>` to build a specific service or `make build` to build all services.

linux/amd64 is consider supported, other build options may work.

## Start, Stop & Restart

`make start` or `docker-compose -f docker-compose.yaml up -d --remove-orphans`

`make stop` or `docker-compose -f docker-compose.yaml rm -s -f`

`make restart`

## Swagger

### Endpoint

`GET http://<apigw-url>/swagger/doc.json`

or with web browser: `http://<apigw-url>/swagger/index.html`
