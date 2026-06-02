#!/bin/sh

# pam-ssh-agent installer script for RHEL/Fedora/Debian
# Script build 2026060201

LOG_FILE=/var/log/pam-ssh-agent-sfx.log
SOURCE_PAM_LIB=libpam_ssh_agent.so
DEBIAN_DEST_DIR=/lib/x86_64-linux-gnu/security
EL_DEST_DIR=/usr/lib64/security
DEST_PAM_LIB=pam_ssh_agent.so

# Compiled on RHEL7 so we get a very old glibc version
# which should be compatible with almost all supported linux distributions as of 2026
VERSION=0.95-glibc2.17+

log() {
    __log_line="${1}"
    __log_level="${2:-INFO}"

    __log_line="${__log_level}: ${__log_line}"
    echo "${__log_line}" >> "${LOG_FILE}"
    echo "${__log_line}"

    if [ "${__log_level}" = "ERROR" ]; then
        POST_INSTALL_SCRIPT_GOOD=false
    fi
}

log_quit() {
    log "${1}" "${2}"
    log "Exiting script"
    exit 1
}

get_el_version() {
    if [ -f /etc/os-release ]; then
    # DIST must contain "rhel", "almalinux", "debian", "ubuntu" or alike
    # FLAVOR will contain "rhel" or "debian"
	# The following awk line has been tested on almalinux 8, almalinux 9, rhel 10, almalinux 10, debian 12, debian 13 and ubuntu 22
        DIST=$(awk '{ if ($1~/^ID=/) { sub("ID=","", $0); gsub("\"","", $0); print tolower($0) }}' /etc/os-release)
        RELEASE=0
        if grep 'ID="rhel"' /etc/os-release > /dev/null || grep 'ID_LIKE="*rhel*' /etc/os-release > /dev/null; then
            FLAVOR=rhel
        elif grep 'ID=*debian*' /etc/os-release > /dev/null; then
            FLAVOR=debian
        elif grep 'ID=*ubuntu*' /etc/os-release > /dev/null; then
            FLAVOR=debian
        else
            log_quit "Cannot determine OS flavor from /etc/os-release"
        fi
    else
        log_quit "No /etc/os-release file found"
    fi
}

get_el_version
log "Detected ${FLAVOR} Linux flavor"
if [ "${FLAVOR}" = "rhel" ]; then
    DST_FILE="${EL_DEST_DIR}/${DEST_PAM_LIB}"
elif [ "${FLAVOR}" = "debian" ]; then
    DST_FILE="${DEBIAN_DEST_DIR}/${DEST_PAM_LIB}"
fi
log "Copying ${SOURCE_PAM_LIB} ${VERSION} to ${DST_FILE}"
cp "${SOURCE_PAM_LIB}" "${DST_FILE}"
result=$?
if [ $result -ne 0 ]; then
        log "Cannot copy library to ${DST_FILE}"
        exit $result
fi
chmod 644 "${DST_FILE}"
result=$?
if [ $result -ne 0 ]; then
        log "Cannot set mod 664 for ${DST_FILE}"
        exit $result
else
        log "Installation successful"
fi
exit $result