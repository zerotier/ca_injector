DOCKER_IMAGE=ca-injector-test
DOCKER_RUN_DEBIAN=docker run -e RUST_BACKTRACE=full -it --rm -v ${PWD}:/root/ca_injector -v ${PWD}/debian/.rustup:/root/.rustup -v ${PWD}/debian/.cargo:/root/.cargo ${DOCKER_IMAGE}:debian

test: build
	mkdir -p debian rhel
	${DOCKER_RUN_DEBIAN} 

build:
	docker build -f Dockerfile.debian -t ${DOCKER_IMAGE}:debian .
