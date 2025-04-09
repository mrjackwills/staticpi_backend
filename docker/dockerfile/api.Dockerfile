#############
## Builder ##
#############

FROM --platform=$BUILDPLATFORM rust:1.86.0-slim-bullseye AS builder

WORKDIR /usr/src

# Create blank project
RUN cargo new staticpi

# We want dependencies cached, so copy those first
COPY Cargo.* /usr/src/staticpi/

# Set the working directory
WORKDIR /usr/src/staticpi

# Prepared statements required to build for sqlx macros
COPY .sqlx /usr/src/staticpi/.sqlx

# This is a dummy build to get the dependencies cached - probably not needed - as run via a github action
RUN cargo build --release

# Now copy in the rest of the sources
COPY src /usr/src/staticpi/src/

## Touch main.rs to prevent cached release build
RUN touch /usr/src/staticpi/src/main.rs

# This is the actual application build
RUN cargo build --release

#############W
## Runtime ##
#############

FROM --platform=$BUILDPLATFORM ubuntu:22.04

ARG DOCKER_GUID=1000 \
	DOCKER_UID=1000 \
	DOCKER_APP_USER=app_user \
	DOCKER_APP_GROUP=app_group

RUN apt-get update \
	&& apt-get install -y ca-certificates curl \
	&& update-ca-certificates \
	&& groupadd --gid ${DOCKER_GUID} ${DOCKER_APP_GROUP} \
	&& useradd --create-home --no-log-init --uid ${DOCKER_UID} --gid ${DOCKER_GUID} ${DOCKER_APP_USER} \
	&& mkdir /logs \
	&& chown ${DOCKER_APP_USER}:${DOCKER_APP_GROUP} /logs

WORKDIR /app

COPY --chown=${DOCKER_APP_USER}:${DOCKER_APP_GROUP} ./docker/healthcheck/health_api.sh /healthcheck/
RUN chmod +x /healthcheck/health_api.sh

COPY --from=builder /usr/src/staticpi/target/release/staticpi /app/

# Copy from host filesystem - used when debugging
# COPY --chown=${DOCKER_APP_USER}:${DOCKER_APP_GROUP} target/release/staticpi /app

USER ${DOCKER_APP_USER}

CMD ["/app/staticpi"]