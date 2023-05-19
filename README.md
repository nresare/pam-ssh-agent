# A PAM module for authenticating using ssh-agent

The goal of this project is to provide a PAM authentication module determining the identity
of user based on a signature request and response sent via the ssh-agent protocol to a potentially
remote `ssh-agent`.

One scenario that this module can be used in is to grant escalated privileges on a remote
system with the `sudo` command where the identity of the user is confirmed by their ability
to provide a signature made with a local ssh-agent and a private key that never leaves the
designated hardware.

This project is re-implementation of the pam_ssh_agent_auth module but does not share
any code with that project. The eventual goal of this module is to be functionally equivalent
and a drop-in replacement instead of pam_ssh_agent_auth.

## Project goals

Since this is security sensitive software and a bug could easily result in undue privilege
escalation, the main goal of this project is to be robust and easy to follow for would-be
reviewers.

The implementation leans heavily on modules available in the Rust ecosystem that implements
the different parts needed for the overall functionality, most notably the pam, ssh-key, 
and ssh-agent-client-rs crates. Using upstream libraries directly is intended to make it
easier to ensure that implementation issues with security implication gets addressed in a
timely manner. A secondary benefit is that supporting a wide range of algorithms is easier.

## License

Licensed under either of the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or the
[MIT license](http://opensource.org/licenses/MIT) at your option.

### Contribution licensing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
