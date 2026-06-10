#!/bin/sh
set -ex
VERSION=0.9.7
# this version is the one that is available in both ubuntu 24.04 updates and in 26.04
# this variable needs to be updated in lock-step with the version in debian/control and debian/rules
RUST_VERSION=1.91
PATH=/usr/lib/rust-${RUST_VERSION}/bin:/usr/bin

rm -rf vendor
cargo vendor-filterer --platform "*-unknown-linux-gnu"
tar cfJ ../pam-ssh-agent_${VERSION}.orig-vendor.tar.xz vendor

tar cfJ ../pam-ssh-agent_${VERSION}.orig.tar.xz src examples tests \
 .github LICENSE* *.md create-deb-dsc.sh rust-toolchain.toml Cargo*

debuild -S -sa
