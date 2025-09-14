#!/usr/bin/env bash
# Hardened, organized YARA installation & maintenance script (Ubuntu/Debian)
# Responsibilities:
#  - Build (if not present or version mismatch)
#  - Update signature-base repo
#  - Run local rule compilation script
#  - (Optional) deploy Wazuh active response script when requested

set -Eeuo pipefail
IFS=$'\n\t'

# -------------------- configuration --------------------
YARA_VERSION="${YARA_VERSION:-4.4.0}"
YARA_PREFIX="${YARA_PREFIX:-/usr/local}"
YARA_SRC_DIR="${YARA_SRC_DIR:-/usr/share/yara}"
SIGBASE_REPO="https://github.com/Neo23x0/signature-base.git"
SIGBASE_DIR="${SIGBASE_DIR:-${YARA_PREFIX}/signature-base}"
LOCAL_UPDATE_SCRIPT="yara_update_rules.sh"   # relative to script dir
ACTIVE_RESPONSE_SOURCE="yara-active-response.sh" # relative to script dir
ACTIVE_RESPONSE_TARGET="/var/ossec/active-response/bin/yara.sh"
DECODER_SOURCE="yara_decoders.xml"
DECODER_TARGET_DIR="/var/ossec/etc/decoders.d"
YARA_ARCHIVE_SHA256="${YARA_ARCHIVE_SHA256:-}"  # optional
DEPLOY_ACTIVE_RESPONSE="${DEPLOY_ACTIVE_RESPONSE:-false}" # or pass --deploy-active-response

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -------------------- helpers --------------------
log() { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }
die() { echo "[-] $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
require() { have "$1" || die "Required command '$1' not found"; }
need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root (or with sudo)."; }

usage() {
cat <<EOF
Usage: $0 [options]
Options:
	--version <ver>                 Install specific YARA version (default: $YARA_VERSION)
	--deploy-active-response        Copy active response script to Wazuh path
	--skip-build                    Skip building (still update rules)
	--force-rebuild                 Rebuild even if version already installed
	--help                          Show this help

Environment overrides:
	YARA_VERSION, YARA_PREFIX, YARA_SRC_DIR, SIGBASE_DIR, DEPLOY_ACTIVE_RESPONSE

Examples:
	YARA_VERSION=4.5.0 sudo $0
	sudo $0 --deploy-active-response
EOF
}

fetch() {
	local url="$1" dest="$2"
	if [[ -f "$dest" ]]; then
		log "Archive already present: ${dest##*/}"
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
	[[ "$actual" == "$expected" ]] || die "SHA256 mismatch for $file (expected $expected got $actual)"
	log "SHA256 verified for ${file##*/}"
}

installed_version_matches() {
	if have yara; then
		local v
		v=$(yara --version 2>/dev/null | awk '{print $2}') || true
		[[ "$v" == "$YARA_VERSION" ]] && return 0
	fi
	return 1
}

install_build_deps() {
	log "Installing build dependencies"
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -y -qq
	apt-get install -y --no-install-recommends \
		automake jq libtool libssl-dev make gcc pkg-config git libjansson-dev libmagic-dev curl ca-certificates
}

prepare_workspace() { mkdir -p "$YARA_SRC_DIR"; }

build_yara() {
	local archive="v${YARA_VERSION}.tar.gz"
	local url="https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz"
	local src_subdir="yara-${YARA_VERSION}"
	pushd "$YARA_SRC_DIR" >/dev/null
	fetch "$url" "$archive"
	verify_sha256 "$archive" "$YARA_ARCHIVE_SHA256"
	[[ -d "$src_subdir" ]] || { log "Extracting ${archive}"; tar -xzf "$archive"; }
	pushd "$src_subdir" >/dev/null
	[[ -f configure ]] || { log "Running bootstrap.sh"; ./bootstrap.sh; }
	log "Configuring build"
	./configure --prefix="$YARA_PREFIX" --enable-cuckoo --enable-magic --enable-dotnet --with-crypto
	log "Building YARA"
	make -j"$(nproc || echo 2)"
	log "Installing YARA"
	make install
	popd >/dev/null
	popd >/dev/null
	hash -r || true
}

clone_signature_base() {
	if [[ -d "$SIGBASE_DIR/.git" ]]; then
		log "Updating signature-base"
		git -C "$SIGBASE_DIR" pull --ff-only || warn "Git pull failed"
	else
		log "Cloning signature-base"
		git clone --depth 1 "$SIGBASE_REPO" "$SIGBASE_DIR" || warn "Clone failed"
	fi
}

run_local_rule_update() {
	local script="$SCRIPT_DIR/$LOCAL_UPDATE_SCRIPT"
	if [[ -x "$script" ]]; then
		log "Executing local rule update script: $LOCAL_UPDATE_SCRIPT"
		bash "$script" || warn "Rule update script returned non-zero"
	else
		warn "Local rule update script not found or not executable: $script"
	fi
}

deploy_active_response() {
	local src="$SCRIPT_DIR/$ACTIVE_RESPONSE_SOURCE"
	if [[ ! -f "$src" ]]; then
		warn "Active response source script missing: $src"
		return 0
	fi
	mkdir -p "$(dirname "$ACTIVE_RESPONSE_TARGET")"
	install -m 750 -o root -g wazuh "$src" "$ACTIVE_RESPONSE_TARGET" || warn "Failed to install active response script"
	mkdir -p /tmp/quarantined || true
	chmod 750 /tmp/quarantined || true
	log "Active response script deployed to $ACTIVE_RESPONSE_TARGET"

	# Deploy decoder if present
	local decoder_src="$SCRIPT_DIR/$DECODER_SOURCE"
	if [[ -f "$decoder_src" ]]; then
		mkdir -p "$DECODER_TARGET_DIR"
		install -m 640 -o root -g wazuh "$decoder_src" "$DECODER_TARGET_DIR/$DECODER_SOURCE" || warn "Failed to install decoder file"
		log "Decoder installed to $DECODER_TARGET_DIR/$DECODER_SOURCE"
	else
		warn "Decoder source not found: $decoder_src"
	fi
}

summary() {
	if have yara; then
		log "YARA version: $(yara --version 2>/dev/null || echo unknown)"
	else
		warn "YARA binary not found after build"
	fi
	log "Signature-base path: $SIGBASE_DIR"
}

# -------------------- argument parsing --------------------
FORCE_REBUILD=false
SKIP_BUILD=false
while [[ $# -gt 0 ]]; do
	case "$1" in
		--version) shift; YARA_VERSION="${1:?Missing version}" ;;
		--force-rebuild) FORCE_REBUILD=true ;;
		--skip-build) SKIP_BUILD=true ;;
		--deploy-active-response) DEPLOY_ACTIVE_RESPONSE=true ;;
		--help|-h) usage; exit 0 ;;
		*) die "Unknown argument: $1" ;;
	esac
	shift || true
done

main() {
	need_root
	install_build_deps
	if ! $SKIP_BUILD; then
		if installed_version_matches && ! $FORCE_REBUILD; then
			log "YARA v${YARA_VERSION} already installed (use --force-rebuild to rebuild)"
		else
			prepare_workspace
			build_yara
		fi
	else
		log "Skipping build phase (--skip-build)"
	fi
	clone_signature_base
	run_local_rule_update
	if [[ "$DEPLOY_ACTIVE_RESPONSE" == true ]]; then
		deploy_active_response
	fi
	summary
	log "Done."
}

main "$@"