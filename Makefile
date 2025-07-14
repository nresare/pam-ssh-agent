CARGO_VERSION = 1.82
build:
	cargo-$(CARGO_VERSION) build --release
	strip target/release/libpam_ssh_agent.so

install:
	install -m644 -D target/release/libpam_ssh_agent.so \
		$(DESTDIR)/lib/${DEB_HOST_MULTIARCH}/security/pam_ssh_agent.so

clean:
	cargo-$(CARGO_VERSION) clean


check:
	PATH=/usr/lib/rust-$(CARGO_VERSION)/bin:$(PATH) cargo-$(CARGO_VERSION) fmt --check
	# it seems the packaging of rust-1.82 and friends is a bit funky
	# if the PATH is not set when invoking clippy and test, the old
	# version will be used
	PATH=/usr/lib/rust-$(CARGO_VERSION)/bin:$(PATH) cargo-$(CARGO_VERSION) clippy
	PATH=/usr/lib/rust-$(CARGO_VERSION)/bin:$(PATH) cargo-$(CARGO_VERSION) test

srpm:
	echo "BUILD: create SRPM like COPR is doing"
	make -f ./.copr/Makefile srpm spec="pam_ssh_agent.spec"
