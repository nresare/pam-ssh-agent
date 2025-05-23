build:
	cargo build --release
	strip target/release/libpam_ssh_agent.so

install:
	install -m644 -D target/release/libpam_ssh_agent.so \
		$(DESTDIR)/lib/${DEB_HOST_MULTIARCH}/security/pam_ssh_agent.so

clean:
	cargo clean


check:
	cargo fmt --check
	cargo clippy
	cargo test

srpm:
	echo "BUILD: create SRPM like COPR is doing"
	make -f ./.copr/Makefile srpm spec="pam_ssh_agent.spec"
