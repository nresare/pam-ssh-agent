#!/bin/sh
set -ex
VERSION=0.9.4
RUST_VERSION=1.82
PATH=/usr/lib/rust-${RUST_VERSION}/bin:/usr/bin

rm -rf vendor
cargo vendor-filterer --platform "*-unknown-linux-gnu"
tar cfJ ../pam-ssh-agent_${VERSION}.orig-vendor.tar.xz vendor

tar cfJ ../pam-ssh-agent_${VERSION}.orig.tar.xz src examples tests \
 .github LICENSE* README* create-deb-dsc.sh Cargo*

debuild -S -sa
