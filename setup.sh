#!/usr/bin/env bash
# FTA one-shot setup: detect the Linux distribution, install a JDK 17 and the pinned Android SDK
# packages, write local configuration, then build and test everything (tools/build.sh).
#
#   ./setup.sh                      interactive: asks before installing system packages and shows SDK licenses
#   ./setup.sh -y --accept-licenses unattended (CI, containers)
#   ./setup.sh --check              report what is present / missing, change nothing (exit 1 if something is missing)
#   ./setup.sh --plan               machine-readable decisions (key=value), change nothing
#
# Everything the build depends on is pinned in the "Pinned toolchain" block below; CI runs this exact
# script on Debian 12, Ubuntu 24.04, Fedora and Arch containers.
set -euo pipefail

# ----------------------------------------------------------------------------- pinned toolchain
JDK_MAJOR=17                                   # AGP 8.5 needs a JDK 17 (not a JRE: javac is required)
CMDLINE_TOOLS_BUILD=11076708                   # Android command-line tools 12.0
CMDLINE_TOOLS_SHA256=2d2d50857e4eb553af5a6dc3ad507a17adf43d115264b1afc116f95c92e5e258
SDK_PACKAGES=("platforms;android-34" "build-tools;34.0.0")   # compileSdk 34; AGP 8.5 default build-tools
OPTIONAL_SDK_PACKAGES=("platform-tools")       # adb, to install the APKs on a phone (not needed to build)
TEMURIN_VERSION="17.0.13+11"                   # used only when the distribution has no JDK 17 package
# ------------------------------------------------------------------------------------------------

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS_RELEASE=${FTA_OS_RELEASE:-/etc/os-release}            # overridable for tests
JVM_DIRS=${FTA_JVM_DIRS:-"/usr/lib/jvm /usr/lib64/jvm /usr/java /opt/java $HOME/.local/share/fta"}
FTA_HOME=${FTA_HOME:-$HOME/.local/share/fta}             # where a downloaded JDK goes
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/fta

PINNED_JDK=0; YES=0; ACCEPT=0; MODE=setup; BUILD=1; TESTS=1; WITH_ADB=1; SDK_DIR=""; JDK_OVERRIDE=""; FORCE_ARCH=0; BUILD_TYPE=release

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; cat <<EOF

options:
  -y, --yes              install system packages without asking
  --accept-licenses      accept the Android SDK licenses non-interactively (read them first: sdkmanager --licenses)
  --sdk DIR              Android SDK location (default: \$ANDROID_HOME, \$ANDROID_SDK_ROOT, android/local.properties, ~/Android/Sdk)
  --jdk DIR              use this JDK 17 instead of auto-detection
  --pinned-jdk           always use the exact pinned Temurin $TEMURIN_VERSION (bit-for-bit identical toolchain everywhere)
  --no-build             set up only, do not build
  --skip-tests           build without running the test suites
  --debug                build debug APKs instead of release
  --no-adb               do not install platform-tools (adb)
  --force-arch           try anyway on a non-x86_64 machine (Google ships the Linux build tools for x86_64 only)
  --check                report status only
  --plan                 print decisions as key=value lines (used by tools/tests/test_setup.py)
  -h, --help             this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes) YES=1 ;;
    --accept-licenses) ACCEPT=1 ;;
    --sdk) SDK_DIR=${2:?--sdk needs a directory}; shift ;;
    --jdk) JDK_OVERRIDE=${2:?--jdk needs a directory}; shift ;;
    --pinned-jdk) PINNED_JDK=1 ;;
    --no-build) BUILD=0 ;;
    --skip-tests) TESTS=0 ;;
    --debug) BUILD_TYPE=debug ;;
    --no-adb) WITH_ADB=0 ;;
    --force-arch) FORCE_ARCH=1 ;;
    --check) MODE=check ;;
    --plan) MODE=plan ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

# ----------------------------------------------------------------------------- output helpers
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; N=$'\e[0m'; else B=""; G=""; Y=""; R=""; N=""; fi
step() { [ "$MODE" = plan ] || printf '%s▸ %s%s\n' "$B" "$*" "$N"; }
ok()   { [ "$MODE" = plan ] || printf '  %s✔%s %s\n' "$G" "$N" "$*"; }
warn() { [ "$MODE" = plan ] || printf '  %s!%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s✖ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }
plan() { [ "$MODE" = plan ] && printf '%s=%s\n' "$1" "$2"; return 0; }

# ----------------------------------------------------------------------------- distribution
OS_ID=unknown; OS_LIKE=""; OS_NAME="unknown Linux"; OS_VERSION=""
osr() { sed -n "s/^$1=//p" "$OS_RELEASE" | head -1 | tr -d "\"'"; }   # read, never execute, os-release
detect_os() {
  [ -r "$OS_RELEASE" ] || return 0
  OS_ID=$(osr ID); OS_ID=${OS_ID:-unknown}
  OS_LIKE=$(osr ID_LIKE)
  OS_NAME=$(osr PRETTY_NAME); OS_NAME=${OS_NAME:-$OS_ID}
  OS_VERSION=$(osr VERSION_ID)
}

PM=none
pkg_manager() {
  for id in $OS_ID $OS_LIKE; do
    case "$id" in
      debian|ubuntu|linuxmint|pop|raspbian|kali|elementary|zorin|neon) PM=apt; return ;;
      fedora|rhel|centos|rocky|almalinux|ol|amzn) PM=dnf; return ;;
      arch|archarm|manjaro|endeavouros|garuda) PM=pacman; return ;;
      opensuse*|suse|sles) PM=zypper; return ;;
      alpine) PM=apk; return ;;
    esac
  done
}

# Base tools + the JDK package name per package manager.
base_packages() {
  case "$PM" in
    apt) echo "ca-certificates curl unzip git python3 coreutils" ;;
    dnf) echo "ca-certificates curl unzip git python3 coreutils findutils which" ;;
    pacman) echo "ca-certificates curl unzip git python coreutils" ;;
    zypper) echo "ca-certificates curl unzip git python3 coreutils" ;;
  esac
}
jdk_package() {
  case "$PM" in
    apt) echo "openjdk-${JDK_MAJOR}-jdk-headless" ;;
    dnf|zypper) echo "java-${JDK_MAJOR}-openjdk-devel" ;;
    pacman) echo "jdk${JDK_MAJOR}-openjdk" ;;
  esac
}

as_root() {
  if [ "$(id -u)" -eq 0 ]; then "$@"
  elif command -v sudo >/dev/null; then sudo "$@"
  else die "need root to run: $* (install sudo or run as root)"; fi
}

pkg_available() {   # is a package installable from the configured repositories?
  local out   # capture first: `cmd | grep -q` fails under pipefail when grep exits early (SIGPIPE)
  case "$PM" in
    apt) out=$(apt-cache policy "$1" 2>/dev/null || true); [[ $out == *"Candidate: "[0-9]* ]] ;;
    dnf) dnf -q list --available "$1" >/dev/null 2>&1 || dnf -q list --installed "$1" >/dev/null 2>&1 ;;
    pacman) pacman -Si "$1" >/dev/null 2>&1 ;;
    zypper) out=$(zypper -q info "$1" 2>/dev/null || true); [[ $out == *"Name"* ]] ;;
    *) return 1 ;;
  esac
}

fetch() {   # fetch URL FILE: progress bar on a terminal, quiet in CI logs
  if [ -t 2 ]; then curl -fL --retry 3 --progress-bar -o "$2" "$1"; else curl -fsSL --retry 3 -o "$2" "$1"; fi
}

pkg_install() {
  [ $# -gt 0 ] || return 0
  if [ "$YES" -ne 1 ]; then
    [ -t 0 ] || die "would install with $PM: $* (re-run with -y to allow)"
    read -r -p "  Install with $PM: $* ? [Y/n] " ans
    case "${ans:-y}" in y|Y|yes) ;; *) die "cancelled: install them yourself and re-run" ;; esac
  fi
  case "$PM" in
    apt) as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" ;;
    dnf) as_root dnf install -y "$@" ;;
    pacman) as_root pacman -S --needed --noconfirm "$@" ;;
    zypper) as_root zypper --non-interactive install "$@" ;;
  esac
}

pkg_refresh() {
  case "$PM" in
    apt) as_root apt-get update -qq ;;
    pacman) as_root pacman -Sy --noconfirm >/dev/null ;;
    zypper) as_root zypper --non-interactive refresh >/dev/null ;;
    dnf) : ;;   # dnf refreshes metadata itself
  esac
}

# ----------------------------------------------------------------------------- JDK detection
# major version of a Java home, from its `release` file (no JVM start) or `java -version`.
java_major() {
  local home=$1 v=""
  if [ -r "$home/release" ]; then v=$(sed -n 's/^JAVA_VERSION="\([^"]*\)".*/\1/p' "$home/release"); fi
  if [ -z "$v" ] && [ -x "$home/bin/java" ]; then
    v=$("$home/bin/java" -version 2>&1 | sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -1)
  fi
  [ -n "$v" ] || return 1
  case "$v" in 1.*) v=${v#1.} ;; esac
  echo "${v%%[.+-]*}"
}

JDK_HOME=""; JRE_ONLY=()
find_jdk() {
  local cands=() d m
  [ -n "$JDK_OVERRIDE" ] && cands+=("$JDK_OVERRIDE")
  [ -n "${JAVA_HOME:-}" ] && cands+=("$JAVA_HOME")
  for d in $JVM_DIRS; do
    [ -d "$d" ] || continue
    for c in "$d"/*; do [ -d "$c" ] && [ ! -L "$c" ] && cands+=("$c"); done
  done
  if [ -z "${FTA_IGNORE_PATH_JDK:-}" ] && command -v javac >/dev/null; then   # test hook: FTA_IGNORE_PATH_JDK=1
    cands+=("$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")")
  fi
  for d in ${cands[@]+"${cands[@]}"}; do
    m=$(java_major "$d" 2>/dev/null) || continue
    [ "$m" = "$JDK_MAJOR" ] || continue
    if [ -x "$d/bin/javac" ]; then JDK_HOME=$d; return 0; fi
    JRE_ONLY+=("$d")
  done
  [ -n "$JDK_OVERRIDE" ] && die "--jdk $JDK_OVERRIDE is not a JDK $JDK_MAJOR (needs bin/javac)"
  return 1
}

download_temurin() {
  local arch tag file url dest="$FTA_HOME/jdk-$TEMURIN_VERSION"
  case "$(uname -m)" in x86_64) arch=x64 ;; aarch64) arch=aarch64 ;; *) die "no Temurin build for $(uname -m)" ;; esac
  if [ -x "$dest/bin/javac" ]; then JDK_HOME=$dest; return; fi
  tag="jdk-${TEMURIN_VERSION/+/%2B}"
  file="OpenJDK${JDK_MAJOR}U-jdk_${arch}_linux_hotspot_${TEMURIN_VERSION/+/_}.tar.gz"
  url="https://github.com/adoptium/temurin${JDK_MAJOR}-binaries/releases/download/$tag/$file"
  mkdir -p "$CACHE" "$FTA_HOME"
  step "Downloading Eclipse Temurin $TEMURIN_VERSION"
  fetch "$url" "$CACHE/$file" || die "download failed: $url"
  fetch "$url.sha256.txt" "$CACHE/$file.sha256.txt" || die "download failed: $url.sha256.txt"
  (cd "$CACHE" && sha256sum -c "$file.sha256.txt" >/dev/null) || die "checksum mismatch for $file"
  rm -rf "$dest.tmp" && mkdir -p "$dest.tmp"
  tar -xzf "$CACHE/$file" -C "$dest.tmp" --strip-components=1
  mv "$dest.tmp" "$dest"
  JDK_HOME=$dest
  ok "JDK installed in $dest"
}

# ----------------------------------------------------------------------------- Android SDK
resolve_sdk_dir() {
  if [ -z "$SDK_DIR" ]; then
    if [ -n "${ANDROID_HOME:-}" ]; then SDK_DIR=$ANDROID_HOME
    elif [ -n "${ANDROID_SDK_ROOT:-}" ]; then SDK_DIR=$ANDROID_SDK_ROOT
    elif [ -f "$ROOT/android/local.properties" ] && grep -q '^sdk.dir=' "$ROOT/android/local.properties"; then
      SDK_DIR=$(sed -n 's/^sdk.dir=//p' "$ROOT/android/local.properties" | head -1)
    else SDK_DIR=$HOME/Android/Sdk; fi
  fi
}

sdkmanager_bin() { echo "$SDK_DIR/cmdline-tools/latest/bin/sdkmanager"; }

missing_sdk_packages() {   # prints SDK packages whose directory is absent
  local p dir wanted=("${SDK_PACKAGES[@]}")
  [ "$WITH_ADB" = 1 ] && wanted+=("${OPTIONAL_SDK_PACKAGES[@]}")
  for p in "${wanted[@]}"; do
    dir="$SDK_DIR/${p//;//}"
    [ -f "$dir/package.xml" ] || [ -f "$dir/source.properties" ] || echo "$p"
  done
}

install_cmdline_tools() {
  [ -x "$(sdkmanager_bin)" ] && { ok "Android command-line tools present"; return; }
  local zip="commandlinetools-linux-${CMDLINE_TOOLS_BUILD}_latest.zip"
  mkdir -p "$CACHE" "$SDK_DIR/cmdline-tools"
  step "Downloading Android command-line tools ($CMDLINE_TOOLS_BUILD)"
  if [ ! -f "$CACHE/$zip" ]; then
    fetch "https://dl.google.com/android/repository/$zip" "$CACHE/$zip.part" \
      || die "download failed: https://dl.google.com/android/repository/$zip"
    mv "$CACHE/$zip.part" "$CACHE/$zip"
  fi
  echo "$CMDLINE_TOOLS_SHA256  $CACHE/$zip" | sha256sum -c - >/dev/null \
    || { rm -f "$CACHE/$zip"; die "checksum mismatch for $zip (deleted; re-run to download again)"; }
  rm -rf "$SDK_DIR/cmdline-tools/latest" "$SDK_DIR/cmdline-tools/.tmp"
  unzip -q "$CACHE/$zip" -d "$SDK_DIR/cmdline-tools/.tmp"
  mv "$SDK_DIR/cmdline-tools/.tmp/cmdline-tools" "$SDK_DIR/cmdline-tools/latest"
  rmdir "$SDK_DIR/cmdline-tools/.tmp"
  ok "command-line tools in $SDK_DIR/cmdline-tools/latest"
}

install_sdk_packages() {
  local sm; sm=$(sdkmanager_bin)
  local missing; mapfile -t missing < <(missing_sdk_packages)
  if [ "${#missing[@]}" -eq 0 ]; then ok "SDK packages present: ${SDK_PACKAGES[*]}"; return; fi
  step "Android SDK licenses"
  if [ "$ACCEPT" = 1 ]; then
    yes 2>/dev/null | JAVA_HOME=$JDK_HOME "$sm" --sdk_root="$SDK_DIR" --licenses >/dev/null || true
  elif [ -t 0 ]; then
    JAVA_HOME=$JDK_HOME "$sm" --sdk_root="$SDK_DIR" --licenses
  else
    die "the SDK licenses must be accepted: run '$sm --licenses' or re-run with --accept-licenses"
  fi
  step "Installing SDK packages: ${missing[*]}"
  JAVA_HOME=$JDK_HOME "$sm" --sdk_root="$SDK_DIR" --install "${missing[@]}" | grep -v '^\[=*' || true
  mapfile -t missing < <(missing_sdk_packages)
  [ "${#missing[@]}" -eq 0 ] || die "SDK packages still missing: ${missing[*]} (licenses not accepted?)"
  ok "SDK packages installed"
}

write_config() {
  printf '# generated by setup.sh – machine specific, not committed\nsdk.dir=%s\n' "$SDK_DIR" > "$ROOT/android/local.properties"
  cat > "$ROOT/.fta-env" <<EOF
# generated by setup.sh – source it before building by hand:  . ./.fta-env
export JAVA_HOME="$JDK_HOME"
export ANDROID_HOME="$SDK_DIR"
export PATH="\$JAVA_HOME/bin:\$ANDROID_HOME/platform-tools:\$PATH"
EOF
  ok "wrote android/local.properties and .fta-env"
}

# ----------------------------------------------------------------------------- main
detect_os
pkg_manager
ARCH=$(uname -m)
plan os_id "$OS_ID"; plan os_like "$OS_LIKE"; plan os_version "$OS_VERSION"; plan pkg_manager "$PM"; plan arch "$ARCH"

step "System: $OS_NAME ($ARCH), package manager: $PM"
if [ "$ARCH" != x86_64 ]; then
  plan arch_supported no
  [ "$FORCE_ARCH" = 1 ] || [ "$MODE" != setup ] || die "Google ships the Android build tools (aapt2) for Linux x86_64 only; build in CI or on x86_64 (or --force-arch)"
  warn "non-x86_64 machine: the Android build will probably fail (aapt2 is x86_64-only on Linux)"
else
  plan arch_supported yes
fi
if [ "$PM" = apk ]; then
  plan pm_supported no
  [ "$MODE" != setup ] || die "Alpine (musl) cannot run the glibc Android build tools; use a Debian/Ubuntu/Fedora/Arch container"
elif [ "$PM" = none ]; then
  plan pm_supported no
  warn "unknown distribution: install a JDK $JDK_MAJOR, curl, unzip, git and python3 yourself, then re-run"
else
  plan pm_supported yes
fi

# 1. base tools
need=()
for t in curl unzip git python3 sha256sum; do command -v "$t" >/dev/null || need+=("$t"); done
plan missing_tools "${need[*]:-}"
if [ "${#need[@]}" -gt 0 ]; then
  if [ "$MODE" = setup ] && [ "$PM" != none ]; then
    step "Installing base tools"; pkg_refresh; read -r -a pkgs <<< "$(base_packages)"; pkg_install "${pkgs[@]}"
  else
    warn "missing tools: ${need[*]}"
  fi
else
  ok "base tools present (curl unzip git python3 sha256sum)"
fi
if command -v python3 >/dev/null && ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
  warn "python3 >= 3.9 is needed for the analyzer and tests"
fi

# 2. JDK 17
if [ "$PINNED_JDK" = 1 ]; then
  plan jdk_action "download-temurin:$TEMURIN_VERSION"
  [ "$MODE" = setup ] && download_temurin
  [ -n "$JDK_HOME" ] && ok "JDK $JDK_MAJOR (pinned): $JDK_HOME"
elif find_jdk; then
  plan jdk "$JDK_HOME"; plan jdk_action use
  ok "JDK $JDK_MAJOR: $JDK_HOME"
else
  plan jdk none
  for j in ${JRE_ONLY[@]+"${JRE_ONLY[@]}"}; do warn "$j is Java $JDK_MAJOR but a JRE only (no javac): it cannot compile"; done
  plan jre_only "${JRE_ONLY[*]:-}"
  jpkg=$(jdk_package)
  plan jdk_action "${jpkg:+install-package:$jpkg|}download-temurin:$TEMURIN_VERSION"
  if [ "$MODE" = setup ]; then
    if [ -n "$jpkg" ]; then pkg_refresh; fi
    if [ -n "$jpkg" ] && pkg_available "$jpkg"; then
      step "Installing $jpkg"; pkg_install "$jpkg"
      find_jdk || die "installed $jpkg but no JDK $JDK_MAJOR found in $JVM_DIRS"
    else
      warn "${jpkg:-a JDK $JDK_MAJOR package} is not available from the $PM repositories: using the pinned Temurin build"
      download_temurin
    fi
    ok "JDK $JDK_MAJOR: $JDK_HOME"
  else
    warn "no JDK $JDK_MAJOR (setup would install ${jpkg:-Temurin $TEMURIN_VERSION})"
  fi
fi

# 3. Android SDK
resolve_sdk_dir
plan sdk_dir "$SDK_DIR"
if [ -x "$(sdkmanager_bin)" ]; then plan cmdline_tools present; else plan cmdline_tools "install:$CMDLINE_TOOLS_BUILD"; fi
mapfile -t miss < <(missing_sdk_packages)
plan sdk_missing "${miss[*]:-}"
if [ "$MODE" = setup ]; then
  step "Android SDK in $SDK_DIR"
  install_cmdline_tools
  install_sdk_packages
  write_config
  [ -f "$ROOT/android/suite.keystore" ] || { step "Creating the shared signing key (android/suite.keystore)"; PATH="$JDK_HOME/bin:$PATH" "$ROOT/tools/make_keystore.sh"; }
else
  if [ "${#miss[@]}" -gt 0 ] || [ ! -x "$(sdkmanager_bin)" ]; then warn "Android SDK incomplete in $SDK_DIR: ${miss[*]:-cmdline-tools}"
  else ok "Android SDK complete in $SDK_DIR"; fi
fi

case "$MODE" in
  plan) exit 0 ;;
  check)
    if [ -n "$JDK_HOME" ] && [ "${#miss[@]}" -eq 0 ] && [ -x "$(sdkmanager_bin)" ] && [ "${#need[@]}" -eq 0 ]; then
      ok "ready to build: ./tools/build.sh"; exit 0
    fi
    echo "run ./setup.sh to install what is missing"; exit 1 ;;
esac

# 4. build
if [ "$BUILD" = 1 ]; then
  args=(--"$BUILD_TYPE"); [ "$TESTS" = 1 ] || args+=(--skip-tests)
  "$ROOT/tools/build.sh" "${args[@]}"
else
  ok "setup done. Build with: ./tools/build.sh   (or: . ./.fta-env && cd android && ./gradlew assembleRelease)"
fi
