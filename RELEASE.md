# Documenting the process of making a new release

1. When there is time to cut a new release, create a commit with version updates in Cargo.toml, create-deb-dsc.sh, 
   and debian/changelog. Commit this to a new branch and push it. Anything that needs fixing in the steps below, please 
   create new commits via pull requests on main and then rebase the vesrion update branch on top of it and try again. 
2. Log onto a Fedora box (nypon.noa.re)
   1. Check out the version update branch
   2. Build a .crate with `cargo package`
   3. Copy the .crate to rpm-packaging/pam-ssh-agent
   4. Run `rust2rpm --path _new_crate_` to generate the new spec
   5. Build the .src.rpm with `rpmbuild -bs rust-pam-ssh-agent.spec --define "_sourcedir ." --define "_srcrpmdir ."`
   6. Verify that the .src.rpm can be built with `mock --addrepo=https://download.copr.fedorainfracloud.org/results/noa/rust/fedora-44-aarch64 ./rust-pam-ssh-agent-0.9.7-1.fc44.src.rpm`
3. Log onto an Ubuntu box (hjortron.noa.re)
   1. Check out the version update branch
   2. Generate source packages with ./create-deb-dsc.sh
   3. Verify that the debian/control vendor line is correct by running `CARGO_VENDOR_DIR=vendor /usr/share/cargo/bin/dh-cargo-vendored-sources`
   4. Update debian/control if needed and re-run
   3. Test building the output with `sbuild -d noble ../*.dsc`
4. Merge the version update branch to main
5. Tag the version
6. `cargo publish`
7. In the rpm-pacakging repo
   1. Update release version in Makefile
   2. Update he shasum in crates.sha256
   3. Verify that `make srpm outdir=/tmp/out` works
   4. navigate to the previous build in the [COPR ui](https://copr.fedorainfracloud.org/coprs/noa/rust/builds/)
   7. Click the "Resubmit" button on the previous build
8. On the ubuntu box
   1. Verify that the tagged commit is checked out 
   2. Regeneate signed sources
   3. Upload with `dput ppa:nresare/ppa .dsc`

