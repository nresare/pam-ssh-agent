# A PAM module for authenticating using ssh-agent

The goal of this project is to provide a PAM authentication module determining the identity
of user based on a signature request and response sent via the ssh-agent protocol to a potentially
remote `ssh-agent`.

One scenario that this module can be used in is to grant escalated privileges on a remote
system with the `sudo` command where the identity of the user is confirmed by their ability
to provide a signature made with a local ssh-agent and a private key that never leaves the
designated hardware. I use the [Secretive](https://github.com/maxgoedjen/secretive) app on 
macOS for this purpose.

This project is re-implementation of the [pam_ssh_agent_auth](https://github.com/jbeverly/pam_ssh_agent_auth) 
module but does not share any code with that project. The eventual goal of this module is to be 
functionally equivalent and a drop-in replacement for `pam_ssh_agent_auth`.

This project is currently in a usable state, and has been tested with Ubuntu 24.04. As of now, 
the path expansion patterns that pam_ssh_agent_auth provides are not implemented. In other 
words a single authorized_keys file is expected to be used.

## Project goals

Since this is security sensitive software and a bug could easily result in undue privilege
escalation, the main goal of this project is to be robust and easy to follow for would-be
reviewers.

The implementation leans heavily on crates available in the Rust ecosystem that implements
the different parts needed for the overall functionality, most notably the pam, ssh-key, 
and ssh-agent-client-rs crates. Using upstream libraries directly is intended to make it
easier to ensure that implementation issues with security implication gets addressed in a
timely manner. A secondary benefit is that it is easier to support a wide range of algorithms.

## Usage

* If you are using a debian derived operating system, use `debuild -b` to build a `.deb` package 
  with the shared object and install it with `dpkg`
* install `doas`, to ensure that you have a different way of elevating your privileges than sudo.
  You will need to add a `permit` line in `/etc/doas.conf` for it to work. This is not strictly
  necessary but since this is still experimental 
* Replace the `common-auth` include in `/etc/pam.d/sudo` with `auth  required   pam_ssh_agent.so`
* Configure `sudo` to not drop the `SSH_AUTH_SOCK` environment variable by
  adding `Defaults env_keep += "SSH_AUTH_SOCK"` to the file `/etc/sudoers.d/ssh_agent_env`
* Add the public key that your ssh-agent knows about to `/etc/security/authorized_keys`
* If you are using a systemd based linux system, you can observe the output of this crate using 
  `journalctl -f --facility authpriv`

## Configuration options

PAM modules can be configured using space separated options after `pam_ssh_agent.so` in the applicable
configuration file in `/etc/pam.d`. pam_ssh_agent currently understands the following options

* `debug` This will increase log output to the AUTHPRIV syslog facility
* `file=/file/name` This will modify the file holding the authorized public keys instead of the
  default `/etc/security/authorized_keys`. This path is subject to the variable expansions mentioned below
* `default_ssh_auth_sock=/path/to/ssh_agent_unix_socket` the path to use if the `SSH_AUTH_SOCKET` is not
  set
  
## Variable expansions

> :warning: Using the home directory expansion is unsafe. It allows an attacker with access to an account with sudo
> rights to elevate their privileges with an ssh key of their choosing. If such a setup is desired, configuring
> sudo with the `NOPASSWD` option is a better option as it makes the insecure configuration explicit.

It is possible to use variable expansion in any of the configuration options. In the current age of configuration
management systems, it might make more sense to move the complexity of using the right `authorized_keys` file 
to those systems, but these variable expansions are available to uses that might want them to provide a smooth upgrade
path from `pam_ssh_agent_auth`.

* `~` same as in shells, without specifying a username this expands to the home directory referred to by `PAM_RUSER`, 
  normally the user attempting to authenticate. If a username is specified, the home directory of that user will be
  used such that `~alice` might expand to `/home/alice`
* `%h` same as `~`, the home directory of the user referred to by the PAM item `PAM_RUSER`
* `%H` the value returned by `gethostname(3)`, truncated after the first period such that if `gethostname(3)` returns
  `host.example.com` this `%H` will turn into `host`
* `%f` the value returned by `gethostname(3)`. For the systems I have looked at, this value is not a fully qualified
  domain name but if it was it would be returned. This behaviour, although a bit surprising is consistent with how
  `pam_ssh_agent_auth` works
* `%u` the username of the user attempting to authenticate
* `%U` numeric uid of the user attempting to authenticate

## The `native-crypto` feature

In a [discussion](https://github.com/nresare/pam-ssh-agent/issues/24) about the possibility of having this piece of
software be integrated into commercial upstream distributions, it was mentioned that such distributions might have
a requirement that all crypto operations happens with FIPS validated software. Since the native rust crypto
implementation that this software was using is not yet FIPS validated, but OpenSSL can be made to be, I decided
to implement the option to use OpenSSL instead of the ssh-key crypto implementation using the `native-crypto` feature.

Unless you are someone that has a mandate to only run FIPS validated crypto implementations, you probably don't want
this feature enabled.

## License

Licensed under either of the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or the
[MIT license](http://opensource.org/licenses/MIT) at your option.

## How to contribute

Just open a pull request against https://github.com/nresare/pam-ssh-agent. I have a github action
that runs the test, `cargo fmt` and `cargo clippy` against diffs (as soon as I get around to trigger them)
so it would be nice if you ran `make check` first locally to save a round-trip or two.

### Contribution licensing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
