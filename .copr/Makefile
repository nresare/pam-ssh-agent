rpmdev-spectool:
	if rpm -q rpmdevtools; then echo "RPM rpmdevtools is already installed"; else echo "RPM rpmdevtools need to be installed first"; dnf install -y rpmdevtools; fi

curl:
	if which wget; then echo "RPM wget is already installed"; else echo "RPM wget need to be installed first"; dnf install -y wget; fi

download: rpmdev-spectool curl
	rpmdev-spectool $(spec) | awk '$$1 ~ /^Source/ && $$2 ~ /^http/ { print $$2 }' | while read url; do \
		file=$$(basename $$url); \
		echo "INFO  : download source: $$url to file $$file"; \
		wget -N $$url; \
		r=$$?; \
		if [ $$r -eq 0 ]; then \
			echo "INFO  : download source: $$url (SUCCESS)"; \
		else \
			echo "ERROR : download source: $$url (ERROR)"; \
			exit 1; \
		fi; \
	done

srpm:	download
	if [ -n "$(outdir)" ]; then \
		rpmbuild -bs $(spec) --undefine=_disable_source_fetch --define "_topdir ." --define "_sourcedir ." --define "_srcrpmdir $(outdir)"; \
	else \
		rpmbuild -bs $(spec) --undefine=_disable_source_fetch --define "_topdir ." --define "_sourcedir ." --define "_srcrpmdir ."; \
	fi
