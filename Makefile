build:
	cargo build --release
	strip target/release/libpam_ssh_agent.so

install:
	install -m644 -D target/release/libpam_ssh_agent.so $(DESTDIR)/${DEB_HOST_MULTIARCH}/security/pam_ssh_agent.so
