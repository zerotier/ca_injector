# vim: ft=dockerfile

FROM debian:latest

RUN apt-get update -qq && apt-get install curl libnss3-tools build-essential libssl-dev pkg-config ca-certificates -y

COPY hack/rustup.sh /bin
RUN chmod 755 /bin/rustup.sh

CMD ["bash", "-c", "source /bin/rustup.sh && cd /root/ca_injector && cargo test -- --nocapture"]
