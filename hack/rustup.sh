#!/bin/bash

if [ ! -x $HOME/.cargo/bin/rustup ]
then
  curl -sSL sh.rustup.rs >/tmp/rustup.sh && bash /tmp/rustup.sh -y
fi

if [ -f $HOME/.cargo/env ]
then
  . $HOME/.cargo/env
fi

rustup default stable
