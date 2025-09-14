#!/usr/bin/env bash
# Hardened, idempotent YARA installation script for Ubuntu/Debian systems
set -Eeuo pipefail
IFS=$'\n\t'

# -------------------- configuration --------------------
YARA_VERSION="${YARA_VERSION:-4.4.0}"   # override via env if needed
YARA_PREFIX="${YARA_PREFIX:-/usr/local}" # installation prefix
YARA_SRC_DIR="${YARA_SRC_DIR:-/usr/share/yara}" # build workspace
SIGBASE_REPO="https://github.com/Neo23x0/signature-base.git"
SIGBASE_DIR="${YARA_PREFIX}/signature-base"
# Use local update script shipped with this project instead of repo's (more controlled)
LOCAL_UPDATE_SCRIPT="yara_update_rules.sh"

# Optional expected sha256 for archive (update when version changes)
YARA_ARCHIVE_SHA256="${YARA_ARCHIVE_SHA256:-}" # e.g. 1a2b3c...

# -------------------- helpers --------------------
log() { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }
die() { echo "[-] $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
require() { have "$1" || die "Required command '$1' not found"; }

need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root (or with sudo)."; }

fetch() {
	local url="$1" dest="$2"
	if [[ -f "$dest" ]]; then
		log "Archive already present: ${dest##*/} (skipping download)"
		return 0
	fi
	log "Downloading ${url}"
	curl -fsSL -o "$dest" "$url" || die "Download failed: $url"
}

verify_sha256() {
	local file="$1" expected="$2"
	[[ -z "$expected" ]] && return 0
	require sha256sum
	local actual
	actual=$(sha256sum "$file" | awk '{print $1}')
	if [[ "$actual" != "$expected" ]]; then
		die "SHA256 mismatch for $file (expected $expected got $actual)"
	fi
	log "SHA256 verified for ${file##*/}"
}

already_installed() {
	if have yara; then
		local v
		v=$(yara --version 2>/dev/null | awk '{print $2}') || true
		if [[ "$v" == "$YARA_VERSION" ]]; then
			return 0
		fi
	fi
	return 1
}

install_build_deps() {
	log "Installing build dependencies (apt-get update if needed)"
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -y -qq
	apt-get install -y --no-install-recommends \
		automake jq libtool libssl-dev make gcc pkg-config git libjansson-dev libmagic-dev curl ca-certificates
}

prepare_workspace() {
	mkdir -p "$YARA_SRC_DIR" || die "Unable to create $YARA_SRC_DIR"
}

build_yara() {
	local archive="v${YARA_VERSION}.tar.gz"
	local url="https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz"
	local src_subdir="yara-${YARA_VERSION}"
	pushd "$YARA_SRC_DIR" >/dev/null
	fetch "$url" "$archive"
	verify_sha256 "$archive" "$YARA_ARCHIVE_SHA256"
	if [[ ! -d "$src_subdir" ]]; then
		log "Extracting archive ${archive}"
		tar -xzf "$archive" || die "Extraction failed"
	else
		log "Source directory already exists: $src_subdir"
	fi
	pushd "$src_subdir" >/dev/null
	if [[ ! -f configure ]]; then
		log "Running bootstrap.sh"
		./bootstrap.sh
	fi
	log "Configuring build"
	./configure --prefix="$YARA_PREFIX" --enable-cuckoo --enable-magic --enable-dotnet --with-crypto
	log "Building YARA (parallel)"
	make -j"$(nproc || echo 2)"
	log "Installing YARA"
	make install
	popd >/dev/null
	popd >/dev/null
	hash -r || true
}

clone_signature_base() {
	if [[ -d "$SIGBASE_DIR/.git" ]]; then
		log "signature-base repo exists; pulling latest"
		git -C "$SIGBASE_DIR" pull --ff-only || warn "Git pull failed (continuing)"
	else
		log "Cloning signature-base repository"
		git clone --depth 1 "$SIGBASE_REPO" "$SIGBASE_DIR" || warn "Clone failed"
	fi
}

update_rules() {
    if [[ -x "$LOCAL_UPDATE_SCRIPT" ]]; then
        log "Running local YARA rule update script: $LOCAL_UPDATE_SCRIPT"
        bash "$LOCAL_UPDATE_SCRIPT" || warn "Local rule update script exited non-zero"
    else
        warn "Local rule update script missing: $LOCAL_UPDATE_SCRIPT"
    fi
}

summary() {
	if have yara; then
		log "YARA version installed: $(yara --version 2>/dev/null || echo 'unknown')"
	else
		warn "YARA binary not found in PATH after install. Check $YARA_PREFIX/bin is in PATH."
	fi
	log "Rule repository path: $SIGBASE_DIR"
}

main() {
	need_root
	install_build_deps
	if already_installed; then
		log "YARA v${YARA_VERSION} already installed; skipping build"
	else
		prepare_workspace
		build_yara
	fi
	clone_signature_base
	update_rules
	summary
	log "Completed YARA installation." 
}

main "$@"