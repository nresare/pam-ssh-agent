This is a autosfx installer for pam-ssh-agent for the time that RHEL/Fedora/Debian don't ship official rpms/deb packages for pam-ssh-agent. It has been tested on RHEL8-10/Debian11-13 and Ubuntu 24.

It supposes that you have compiled `pam-ssh-agent` via `cargo build --release` and copied the resulting lib-pam-ssh-agent.so to the same directory as this file.

You may also want to change the `VERSION` variable in the `setup.sh` file to reflect the version of pam-ssh-agent you are installing. The installer script will log its actions to `/var/log/pam-ssh-agent-sfx.log`.

Once you're done, cd to the `autosfx` directory, so the `pam-ssh-agent-installer` directory is a subdirectory and execute the following sfx maker command

```
SETUP_VERSION=$(grep "^VERSION=" pam-ssh-agent-installer/setup.sh | cut -d'=' -f2)
PACKAGE_VERSION=-2
makeself --gzip --sha256 ./pam-ssh-agent-installer ./pam-ssh-agent-installer-${VERSION}${PACKAGE_VERSION}.sh "pam-ssh-agent ${VERSION}" ./setup.sh
```

If you don't have makeself, you can install it via your favorite package manager or downloaded it from github via https://github.com/megastep/makeself/releases/

The resulting script can be executed on any decently recent linux.
The idea is to compile the library on the eldest linux you have, so it will run on every distro which has a glibc version equal or newer than your build machine.

Please note that since we did install the pam-ssh-agent library manually, we won't get security fixes.
If you are a package maintainer, perhaps you could help out to make this library a standard addition to your favorite Linux.