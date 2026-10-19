#!/bin/sh
# Install the Witnessory probe on Linux (Debian, Ubuntu, Raspberry Pi OS, Fedora and others with systemd).
# Needs a 64-bit system and Python 3.10 or newer.
#
#   sudo sh install.sh               install (or upgrade), start, and run at every boot
#   sudo sh install.sh --uninstall   stop and remove the program (keeps the probe's keys and results)
#   sudo sh install.sh --purge       remove everything, including the probe's keys and results
#
# What it does: makes a system user "witnessory-probe" with no login, puts the probe in its own Python environment
# in /opt/witnessory-probe, keeps the probe's keys and results in /var/lib/witnessory-probe, and runs it as a
# sandboxed systemd service. Nothing else on the machine is changed. docs/PROTOCOL.md says what the probe does.
#
# Settings (environment): PACKAGE (what pip installs; default: this release's wheel from GitHub); PREFIX and PROBE_HOME (absolute
# paths ending in "witnessory-probe", no spaces); COORDINATOR (an https address, for a private deployment).
#
# Everything is inside main(), called on the last line: a download cut short runs nothing.
set -eu

main() {
  umask 022                                            # the probe's user must be able to read its program
  PACKAGE="${PACKAGE:-https://github.com/witnessory/probe/releases/download/v0.4.2/witnessory_probe-0.4.2-py3-none-any.whl}"
  PREFIX="${PREFIX:-/opt/witnessory-probe}"
  PROBE_HOME="${PROBE_HOME:-/var/lib/witnessory-probe}"
  USER_NAME="witnessory-probe"
  UNIT="/etc/systemd/system/witnessory-probe.service"

  [ "$(id -u)" -eq 0 ] || die "run as root (sudo sh install.sh)"
  safe_path PREFIX "$PREFIX"
  safe_path PROBE_HOME "$PROBE_HOME"
  [ "$PREFIX" != "$PROBE_HOME" ] || die "PREFIX and PROBE_HOME must be different folders"

  case "${1:-}" in
    --uninstall|--purge) remove "$1"; exit 0 ;;
    "") ;;
    *) die "unknown option: $1 (use --uninstall or --purge)" ;;
  esac

  if [ -n "${COORDINATOR:-}" ]; then
    case "$COORDINATOR" in
      https://*|http://127.0.0.1*|http://localhost*) ;;
      *) die "COORDINATOR must be an https address" ;;
    esac
    case "$COORDINATOR" in *[!A-Za-z0-9:/._-]*) die "COORDINATOR has characters an address cannot have" ;; esac
  fi

  command -v python3 >/dev/null 2>&1 || die "Python 3.10 or newer is needed (for example: apt install python3 python3-venv)"
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || die "Python 3.10 or newer is needed"
  python3 -c 'import sys; sys.exit(0 if sys.maxsize > 2**32 else 1)' || die "a 64-bit system is needed"
  python3 -c 'import venv, ensurepip' 2>/dev/null || die "Python's venv module is missing (for example: apt install python3-venv)"

  if ! id "$USER_NAME" >/dev/null 2>&1; then
    useradd --system --home-dir "$PROBE_HOME" --shell /usr/sbin/nologin "$USER_NAME" 2>/dev/null \
      || useradd --system --home-dir "$PROBE_HOME" --shell /sbin/nologin "$USER_NAME"
  fi
  if [ ! -d "$PROBE_HOME" ]; then
    install -d -o "$USER_NAME" -g "$(id -gn "$USER_NAME")" -m 750 "$PROBE_HOME"
  fi

  say "Installing the probe in $PREFIX ..."
  python3 -m venv "$PREFIX"
  "$PREFIX/bin/pip" install --quiet --upgrade "$PACKAGE"
  "$PREFIX/bin/witnessory-probe" --version

  if [ ! -f "$PROBE_HOME/card.json" ]; then
    if [ -n "${COORDINATOR:-}" ]; then
      as_probe "$PREFIX/bin/witnessory-probe" --home "$PROBE_HOME" init --coordinator "$COORDINATOR"
    else
      as_probe "$PREFIX/bin/witnessory-probe" --home "$PROBE_HOME" init
    fi
  fi

  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    write_unit
    systemctl daemon-reload
    systemctl enable witnessory-probe.service >/dev/null
    systemctl restart witnessory-probe.service          # an upgrade runs the new code
    say "The probe is running, and will start at every boot."
  else
    say "No systemd here: start the probe yourself with"
    say "  sudo -u $USER_NAME $PREFIX/bin/witnessory-probe --home $PROBE_HOME run"
  fi

  say ""
  say "Your probe:      sudo -u $USER_NAME $PREFIX/bin/witnessory-probe --home $PROBE_HOME me"
  say "What it did:     sudo -u $USER_NAME $PREFIX/bin/witnessory-probe --home $PROBE_HOME log"
  say "Pause / resume:  sudo -u $USER_NAME $PREFIX/bin/witnessory-probe --home $PROBE_HOME pause   (or resume)"
  say "Remove:          sudo sh install.sh --uninstall"
}

say() { printf '%s\n' "$*"; }
die() { printf 'witnessory-probe install: %s\n' "$*" >&2; exit 1; }

# An absolute path, no spaces or unusual characters, ending in "witnessory-probe", never a system directory.
safe_path() {
  case "$2" in
    /*/witnessory-probe) ;;
    *) die "$1 must be an absolute path ending in /witnessory-probe (got '$2')" ;;
  esac
  case "$2" in *[!A-Za-z0-9/._-]*|*/../*|*/./*) die "$1 has characters a path here cannot have" ;; esac
  case "$2" in /home/*|/root/*|/tmp/*|/var/tmp/*) die "$1 cannot be under /home, /root or /tmp (the service cannot use them)" ;; esac
}

as_probe() {
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "$USER_NAME" -- "$@"
  else
    su -s /bin/sh "$USER_NAME" -c "$(printf "'%s' " "$@")"
  fi
}

remove() {
  # Every check first, so nothing is removed unless all of it can be.
  if [ -e "$PREFIX" ] && [ ! -x "$PREFIX/bin/witnessory-probe" ]; then
    die "$PREFIX does not look like the probe's program folder; nothing removed"
  fi
  if [ "$1" = "--purge" ] && [ -e "$PROBE_HOME" ] && [ ! -f "$PROBE_HOME/card.json" ] && [ -n "$(ls -A "$PROBE_HOME")" ]; then
    die "$PROBE_HOME does not look like the probe's folder; nothing removed"
  fi
  if command -v systemctl >/dev/null 2>&1 && [ -f "$UNIT" ]; then
    systemctl disable --now witnessory-probe.service >/dev/null 2>&1 || true
    rm -f "$UNIT"
    systemctl daemon-reload
  fi
  # Only folders this installer made: the program's must hold the probe's command.
  [ -e "$PREFIX" ] && rm -rf "$PREFIX"
  if [ "$1" = "--purge" ]; then
    [ -e "$PROBE_HOME" ] && rm -rf "$PROBE_HOME"
    userdel "$USER_NAME" 2>/dev/null || true
    say "Witnessory probe removed, with its keys and results."
  else
    say "Witnessory probe removed. Its keys and results are kept in $PROBE_HOME (remove with --purge)."
  fi
}

write_unit() {
  cat > "$UNIT" <<EOF
[Unit]
Description=Witnessory probe (measures public servers' post-quantum readiness; docs/PROTOCOL.md)
After=network-online.target
Wants=network-online.target

[Service]
User=$USER_NAME
Environment=PYTHONIOENCODING=utf-8
ExecStart=$PREFIX/bin/witnessory-probe --home $PROBE_HOME run
Restart=always
RestartSec=60
TimeoutStopSec=120
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$PROBE_HOME
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes
MemoryMax=256M
CPUQuota=25%
TasksMax=64
Nice=10

[Install]
WantedBy=multi-user.target
EOF
}

main "$@"
