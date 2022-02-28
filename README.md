# ca_injector: inject CA certificates into trust stores

This library is a (as of this writing, incomplete) rust port of [mkcert](https://github.com/FiloSottile/mkcert) to a library. It's purpose is to let you install the CAs of your choosing into various trust stores.

Please see the [docs](https://docs.rs/crate/ca_injector/latest) for more information on use.

Please also note that this library only supports injection into **Linux** trust stores as of this writing. It is planned soon to have OS X and Windows support.

## Author

Erik Hollensbe <erik.hollensbe@zerotier.com>

## License

BSD 3-Clause
