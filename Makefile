DOCKER_IMAGE=ca-injector-test
DOCKER_RUN=docker run -e RUST_BACKTRACE=full -it --rm -v ${PWD}:/root/ca_injector -v ${PWD}/.rustup:/root/.rustup -v ${PWD}/.cargo:/root/.cargo ${DOCKER_IMAGE}

test: build
	mkdir -p .cargo .rustup
	${DOCKER_RUN}

build:
	docker build -t ${DOCKER_IMAGE} .
