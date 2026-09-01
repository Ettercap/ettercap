#!/usr/bin/env bash
#
# Provision an Ubuntu machine to build and run the GTK4 ettercap interface.
#
# This is deliberately a plain shell script with no Cua dependency: it is the
# same set of steps whether it runs inside a Cua cloud sandbox, a local
# container, a CI runner, or a VM someone SSH'd into. harness.py shells out
# to it rather than reimplementing it, so there is exactly one definition of
# "what the GTK4 build needs".
#
# Usage:  provision.sh [--build-only] [--source-dir DIR] [--build-dir DIR]
#
set -euo pipefail

SOURCE_DIR="${SOURCE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
BUILD_DIR="${BUILD_DIR:-${SOURCE_DIR}/build-gtk4}"
SKIP_DEPS=0

while [ $# -gt 0 ]; do
   case "$1" in
      --build-only)  SKIP_DEPS=1 ;;
      --source-dir)  SOURCE_DIR="$2"; shift ;;
      --build-dir)   BUILD_DIR="$2"; shift ;;
      *) echo "unknown argument: $1" >&2; exit 2 ;;
   esac
   shift
done

log() { printf '\n=== %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
#
# The GTK4 interface needs libgtk-4-dev and libadwaita-1-dev on top of what
# .github/workflows/build.yml already installs. libadwaita >= 1.5 is a hard
# requirement (AdwDialog / AdwAlertDialog), which is why this targets Ubuntu
# 24.04 rather than 22.04 -- 22.04 ships GTK 4.6 and libadwaita 1.1, neither
# of which is sufficient.

if [ "$SKIP_DEPS" -eq 0 ]; then
   log "Checking distribution"
   if [ -r /etc/os-release ]; then
      . /etc/os-release
      echo "${PRETTY_NAME:-unknown}"
      case "${VERSION_ID:-}" in
         22.04|20.04|18.04)
            echo "ERROR: Ubuntu ${VERSION_ID} ships libadwaita < 1.5." >&2
            echo "       The GTK4 interface needs 24.04 or newer." >&2
            exit 1
            ;;
      esac
   fi

   log "Installing build dependencies"
   export DEBIAN_FRONTEND=noninteractive

   # Ubuntu 24.04 ships needrestart, which after a library upgrade restarts
   # every service linked against it. Inside a sandbox or CI container that
   # set includes whatever is hosting the session running this script, so the
   # install kills its own caller partway through -- it surfaces as an
   # abrupt transport error or a 502, with no hint that apt caused it.
   # Suppress both the automatic restarts and dpkg starting services at all.
   export NEEDRESTART_MODE=l
   export NEEDRESTART_SUSPEND=1

   SUDO=""
   [ "$(id -u)" -ne 0 ] && SUDO="sudo"

   if [ ! -e /usr/sbin/policy-rc.d ]; then
      printf '#!/bin/sh\nexit 101\n' | $SUDO tee /usr/sbin/policy-rc.d >/dev/null
      $SUDO chmod +x /usr/sbin/policy-rc.d
      trap '$SUDO rm -f /usr/sbin/policy-rc.d' EXIT
   fi

   # Wait for apt to be free rather than failing on it. A fresh Ubuntu cloud
   # image runs apt-daily/unattended-upgrades at boot, and an interrupted
   # earlier run can leave apt holding the lock too. DPkg::Lock::Timeout is
   # set as well, but it does not reliably cover the lists lock that
   # `apt-get update` takes, so poll for the lock holders to go away first.
   wait_for_apt() {
      local waited=0
      # fuser lives in psmisc, which this script installs -- so on a minimal
      # image it may not exist on the first call. Fall back to apt's own
      # timeout in that case rather than failing.
      command -v fuser >/dev/null 2>&1 || { sleep 10; return 0; }
      while $SUDO fuser /var/lib/dpkg/lock-frontend \
                        /var/lib/apt/lists/lock \
                        /var/cache/apt/archives/lock >/dev/null 2>&1; do
         if [ "$waited" -ge 900 ]; then
            echo "ERROR: apt has been locked for ${waited}s, giving up" >&2
            $SUDO fuser -v /var/lib/apt/lists/lock 2>&1 || true
            return 1
         fi
         [ $((waited % 30)) -eq 0 ] && echo "waiting for apt lock (${waited}s)..."
         sleep 5
         waited=$((waited + 5))
      done
   }

   APT="$SUDO apt-get -o DPkg::Lock::Timeout=900"

   wait_for_apt
   $APT update -qq
   # Installed in small groups on purpose: on the shared cloud sandboxes a
   # single large apt transaction keeps the box busy long enough to wedge the
   # agent's command endpoint. Each group is a separate, shorter transaction.
   install_group() {
      wait_for_apt
      $APT install -y --no-install-recommends "$@"
   }

   install_group build-essential cmake bison flex groff pkg-config
   install_group libgtk-4-dev libadwaita-1-dev
   install_group libssl-dev libpcap-dev libnet1-dev libpcre2-dev
   install_group libcurl4-openssl-dev libltdl-dev libncurses-dev \
      libbsd-dev libmaxminddb-dev zlib1g-dev

   # Driving the UI needs an accessibility bus to read the widget tree from,
   # and something to look at it with. On a Kasm/Xfce image most of this is
   # already present; installing it is cheap and makes the script portable to
   # a bare Ubuntu container.
   install_group at-spi2-core python3-pyatspi xvfb x11-utils wmctrl \
      xdotool psmisc

   log "Toolchain versions"
   cmake --version | head -1
   pkg-config --modversion gtk4      | sed 's/^/gtk4:        /'
   pkg-config --modversion libadwaita-1 | sed 's/^/libadwaita:  /'
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

log "Configuring (source=${SOURCE_DIR} build=${BUILD_DIR})"
cmake -S "$SOURCE_DIR" -B "$BUILD_DIR" \
   -DCMAKE_BUILD_TYPE=Debug \
   -DENABLE_GTK=ON \
   -DGTK_BUILD_TYPE=GTK4 \
   -DENABLE_CURSES=ON \
   -DENABLE_PLUGINS=ON \
   -DENABLE_IPV6=ON

log "Building"
# Deliberately throttled: on the 4-vCPU cloud sandboxes, a full-parallel
# build starves the sandbox agent of CPU for long enough that its command
# endpoint stops answering -- and short status polls issued afterwards wedge
# too. `nice -j2` keeps the box responsive. Override with EC_BUILD_JOBS on a
# machine that can take it.
JOBS="${EC_BUILD_JOBS:-2}"
nice -n 19 cmake --build "$BUILD_DIR" -j"$JOBS"

log "Build complete"
ls -la "$BUILD_DIR/src/ettercap" 2>/dev/null || {
   echo "ERROR: ettercap binary not produced" >&2
   exit 1
}

# ---------------------------------------------------------------------------
# Runtime capabilities
# ---------------------------------------------------------------------------
#
# Ettercap opens raw sockets. Granting the binary CAP_NET_RAW/CAP_NET_ADMIN
# lets the GUI run as an unprivileged user, which matters here: a GUI started
# as root does not share the session's accessibility bus, and the harness
# reads the widget tree over AT-SPI. Offline (pcap replay) mode exercises
# most of the interface without needing this at all, so a failure to set the
# capabilities is a warning rather than an error.

if command -v setcap >/dev/null 2>&1; then
   log "Granting capabilities"
   SUDO=""
   [ "$(id -u)" -ne 0 ] && SUDO="sudo"
   $SUDO setcap cap_net_raw,cap_net_admin+eip "$BUILD_DIR/src/ettercap" \
      && echo "ok" \
      || echo "WARNING: setcap failed; live sniffing will need root, offline mode still works"
fi

log "Done"
