# Building Proton Mail Bridge

## Prerequisites
* 64-bit OS:
    - the go-rfc5322 module cannot currently be compiled for 32-bit OSes
* Go 1.24.0
* Bash with basic build utils: make, gcc, sed, find, grep, ...
  - For Windows, it is recommended to use MinGW 64bit shell from [MSYS2](https://www.msys2.org/)
* GCC (Linux), msvc (Windows) or Xcode (macOS)
* Windres (Windows)
* libsecret and libfido2 development files (Linux)
* pkg-config (Linux)

To enable the sending of crash reports using Sentry please set the
`DSN_SENTRY` environment variable with the client key of your sentry project before build.
Otherwise, the sending of crash reports will be disabled.

## Build
Before you start the build **on Windows**, please unset the `MSYSTEM` variable

```bash
export MSYSTEM=
```

### Build Bridge
* in project root run

```bash
make build
```

* The result will be stored in `./cmd/Desktop-Bridge/deploy/${GOOS}/` and packed into `bridge_${GOOS}_${REVISION}.tgz`.
  It contains the `bridge` executable and the `proton-bridge` launcher (with the `.exe` extension on Windows).
* To build only the executables in the project root, run `make build-bridge`.

## Running Bridge
Bridge runs headless. It is configured through a web interface that it serves while it runs.

* By default the web interface listens on `0.0.0.0:8143` over HTTPS, using the self-signed Bridge TLS certificate.
  * `--web-address <host:port>` changes the listening address, for example `--web-address 127.0.0.1:8143`.
  * `--web-no-tls` serves plain HTTP, for use behind a reverse proxy that terminates TLS.
* On the first start, Bridge prints a one-time setup token to the standard output and to the log.
  Open the web interface, enter the setup token and choose the password that protects the web interface.
* The web interface adds, signs out and removes accounts, shows the IMAP and SMTP settings for email clients,
  and changes the Bridge settings. Accounts that require a security key (FIDO2) without an authenticator app
  cannot be signed in from the web interface.
* NOTE: You still need to set up a supported keychain on your system.

## Launchers
Launchers are only included in official distributions and provide the public
key used to verify signed app binaries, allowing the automatic update feature.
See README for more information.

## Tags
Note that repository contains both Bridge and Import-Export apps and they are
not released together. Therefore, each app has own tag prefix. Bridge tags
starts with `br-` and Import-Export tags starts with `ie-`. Both tags continue
with semantic versioning `MAJOR.MINOR.PATCH`. An example of full tag is
`br-1.4.4` or `ie-1.1.2` (current versions in October 2020).

## Useful tests, lints and checks
In order to be able to run following commands please install the development dependencies: 
`make install-dev-dependencies`

* `make test` will run all unit tests
* `make lint` will lint the whole project
* `make -C ./test test` will run the integration tests
* `make run` will build Bridge and start it
