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

This project is currently in a usable state, and has been tested with Ubuntu 22.04. As of now, 
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

* use `debuild -b` to build a `.deb` package with the shared object and install it with `dpkg`
* install `doas`, to ensure that you have a different way of elevating your privileges than sudo.
  You will need to add a `permit` line in `/etc/doas.conf` for it to work
* Replace the `common-auth` include in `/etc/pam.d/sudo` with `auth    required      pam_ssh_agent.so`
* Configure `sudo` to not drop the `SSH_AUTH_SOCK` environment variable by
  adding `Defaults env_keep += "SSH_AUTH_SOCK` to the file `/etc/sudoers.d/ssh_agent_env`
* Add the public key that your ssh-agent knows about to `/etc/security/authorized_keys`

## Configuration options

PAM modules can be configured using space separated options after `pam_ssh_agent.so` in the applicable
configuration file in `/etc/pam.d`. pam_ssh_agent currently understands the following options

* `debug` This will increase log output to the AUTHPRIV syslog facility
* `file=/file/name` This will modify the file holding the authorized public keys instead of the
  default `/etc/security/authorized_keys`.

## License

Licensed under either of the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or the
[MIT license](http://opensource.org/licenses/MIT) at your option.

### Contribution licensing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
