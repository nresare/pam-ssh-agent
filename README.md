# A PAM module for authenticating using ssh-agent

The goal of this project is to provide a PAM authentication module determining the identity of a user based on a
signature request and response sent via the ssh-agent protocol to a potentially remote `ssh-agent`.

One scenario that this module can be used in is to grant escalated privileges on a remote system accessed using `ssh`
with agent forwarding enabled and the `sudo` command. The user proves their identity by signing a challenge using their
private key, and the signature is verified using a public key made available to the `pam-ssh-agent` module on the
server. Combined with a setup where the private part of an authentication keypair is stored in custom hardware such as
a YubiKey, a TPM chip, or the macOS secure enclave, this can provide a high level of security as well as convenience.
I use the [Secretive](https://github.com/maxgoedjen/secretive) app on macOS for this purpose.

This project is re-implementation of the [pam_ssh_agent_auth](https://github.com/jbeverly/pam_ssh_agent_auth) module but does not share any code with that project.
We are pretty close to covering all the features of the original implementation, along with some additional features
such as SSH Certificate based authentication.

## Project goals

Since this is security sensitive software and a bug could easily result in undue privilege escalation, the main goal of
this project is to be robust and easy to follow for would-be reviewers.

The implementation leans heavily on crates available in the Rust ecosystem that implements the different parts needed
for the overall functionality, most notably the `pam`, `ssh-key`, and `ssh-agent-client-rs` crates. Using upstream
libraries directly is intended to make it easier to ensure that implementation issues with security implications gets
addressed in a timely manner. A secondary benefit is that it is easier to support the full of algorithms that OpenSSH
supports.

## Installation and packaging

Getting this software packaged and integrated into upstream Linux distributions is an active goal of this project,
however doing that in a way that conforms to upstream rules and conventions turns out to be a lot of work. If you have
the ability to contribute feel free to have a look at the following issues:

* Fedora/CentOS/Enterprise Linux packaging: https://github.com/nresare/pam-ssh-agent/issues/24
* Ubuntu packaging: https://github.com/nresare/pam-ssh-agent/issues/54
* Arch linux packaging: https://github.com/nresare/pam-ssh-agent/issues/50

While this work is completing, feel free to use https://copr.fedorainfracloud.org/coprs/noa/rust/ that has binary 
packages for Fedora and Enterprise Linux derived distributions. The configuration that is invoked by the copr
infrastructure to build those packages is available from https://github.com/nresare/rpm-packaging The latest version is
also packaged for Ubuntu 24.04 available at https://launchpad.net/~nresare/+archive/ubuntu/ppa where the
`*_sources.changes` and related tarfiles are constructed using the `create-deb-dsc.sh` script.

For other users, it is entirely possible to simply invoke `cargo build --release` and copy the resulting
`target/release/libpam_ssh_agent.so` to the directory that holds your pam modules. Mine is in 
`/lib/x86_64-linux-gnu/security`.

## Example Usage

* First, install the software using one of the methods above.
* install `doas`, to ensure that you have a different way of elevating your privileges than sudo.
  You will need to add a `permit` line in `/etc/doas.conf` for it to work. This is not strictly
  necessary, but especially if you work on remote machines without console access it is good to
  have a backup authentication method set up.
* Replace the `common-auth` include in `/etc/pam.d/sudo` with `auth  required   pam_ssh_agent.so`
* Configure `sudo` to not drop the `SSH_AUTH_SOCK` environment variable by
  adding `Defaults env_keep += "SSH_AUTH_SOCK"` to the file `/etc/sudoers.d/ssh_agent_env`
* Add the public key that your ssh-agent knows about to `/etc/security/authorized_keys`
* If you are using a systemd based linux system, you can observe the output of this crate using 
  `journalctl -f --facility authpriv`

## Configuration options

PAM modules can be configured using space separated options after `pam_ssh_agent.so` in the applicable
configuration file in `/etc/pam.d`. pam_ssh_agent currently understands the following options:

* `debug` Increase log output to the AUTHPRIV syslog facility.
* `file=/file/name` Override/modify the file from which authorized public keys are read. If not
  specified, the default is `/etc/security/authorized_keys`. This path is subject to the variable
  expansions mentioned below.
* `ca_keys_file=/ca/keys/filename`. Read trusted certificate authorities from a file that doesn't
  include any key options prefixes. See below for further information about certificate
  authentication and the subtle format difference in file format compared to `file`.
* `authorized_keys_command=/path/executable` Specify a command that should be run to dynamically
  retrieve/prepare a list of authorized public keys. The command will be passed a single argument
  containing the username of the user requesting authentication. The command should print keys to
  STDOUT in authorized_keys format.
* `autorizxed_keys_command_user=NON_PRIVILEGED_USER` If set, specifies the user that `authorized_keys_command`
  will be executed as. If not specified, the command will be run as the requesting user.
* `default_ssh_auth_sock=/path/to/ssh_agent_unix_socket` the path to use if the `SSH_AUTH_SOCKET` environment variable
  is not set.

## SSH Certificates

Besides authenticating using signatures corresponding to ssh public keys, SSH certificates can also
be used. A certificate is considered valid if the following conditions are met:

* The current time is within the validity period
* The certificate signature is valid and was made by a trusted certificate key
* The username provided to the plugin by the PAM_USER item is in the certificate's list of principals

Just like with OpenSSH there are two ways to specify a certificate authority key. In the same way as the
authorized_keys format, a certificate authority key can be specified alongside the regular ssh keys by being
prefixed by a list of options that include the `cert-authority` option. In the simplest case, this means
that the key is prefixed with `cert-authority` followed by a space and the key in its usual single line format.

The second way to specify certificate authority keys work in the same way as the OpenSSH option `TrustedUserCAKeys`
where keys without the `cert-authority` option are specified, one per line. To enable this mode of operation,
set the `ca_keys_file` option.

## Variable expansions

> :warning: Using the home directory expansion is unsafe. It allows an attacker with access to an account with sudo
> rights to elevate their privileges with an ssh key of their choosing. If such a setup is desired, configuring
> sudo with the `NOPASSWD` option is a better option as it makes the insecure configuration explicit.

It is possible to use variable expansion in any of the configuration options. In the current age of configuration
management systems, it might make more sense to move the complexity of using the right `authorized_keys` file 
to those systems, but these variable expansions are available to users that might want them. It also makes the 
upgrade path from `pam_ssh_agent_auth` smoother as the previous functionality is retained.

* `~` same as in shells, without specifying a username this expands to the home directory referred to by `PAM_USER`, 
  normally the user attempting to authenticate. If a username is specified, the home directory of that user will be
  used such that `~alice` might expand to `/home/alice`.
* `%h` same as `~`, the home directory of the user referred to by the PAM item `PAM_USER`.
* `%H` the value returned by `gethostname(3)`, truncated after the first period such that if `gethostname(3)` returns
  `host.example.com` this `%H` will turn into `host`.
* `%f` the value returned by `gethostname(3)`. For the systems I have looked at, this value is not a fully qualified
  domain name but if it was it would be returned. This behaviour, although a bit surprising is consistent with how
  `pam_ssh_agent_auth` works.
* `%u` the username of the user attempting to authenticate.
* `%U` numeric uid of the user attempting to authenticate.

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
