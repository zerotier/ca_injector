DOCKER_IMAGE=ca-injector-test
DOCKER_RUN_DEBIAN=docker run -e RUST_BACKTRACE=full -it --rm -v ${PWD}:/root/ca_injector -v ${PWD}/debian/.rustup:/root/.rustup -v ${PWD}/debian/.cargo:/root/.cargo ${DOCKER_IMAGE}:debian
DOCKER_RUN_UBUNTU=docker run -e RUST_BACKTRACE=full -it --rm -v ${PWD}:/root/ca_injector -v ${PWD}/ubuntu/.rustup:/root/.rustup -v ${PWD}/ubuntu/.cargo:/root/.cargo ${DOCKER_IMAGE}:ubuntu

test: build
	mkdir -p debian ubuntu
	${DOCKER_RUN_DEBIAN}
	${DOCKER_RUN_UBUNTU}

build:
	docker build -f Dockerfile.debian -t ${DOCKER_IMAGE}:debian .
	docker build -f Dockerfile.ubuntu -t ${DOCKER_IMAGE}:ubuntu .
