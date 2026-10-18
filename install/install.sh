#!/bin/sh
# Install the Witnessory probe on Linux (Debian, Ubuntu, Raspberry Pi OS, Fedora and others with systemd).
#
#   sudo sh install.sh               install, start, and run at every boot
#   sudo sh install.sh --uninstall   stop and remove the program (keeps the probe's keys and results)
#   sudo sh install.sh --purge       remove everything, including the probe's keys and results
#
# What it does: makes a system user "witnessory-probe" with no login, puts the probe in its own Python environment
# in /opt/witnessory-probe, keeps the probe's keys and results in /var/lib/witnessory-probe, and runs it as a
# sandboxed systemd service. Nothing else on the machine is changed. Read docs/PROTOCOL.md for what the probe does.
#
# Settings: PACKAGE (what pip installs; default "witnessory-probe"), PREFIX, PROBE_HOME, COORDINATOR (another
# coordinator than the one the release names, for a private deployment).
set -eu

PACKAGE="${PACKAGE:-witnessory-probe}"
PREFIX="${PREFIX:-/opt/witnessory-probe}"
PROBE_HOME="${PROBE_HOME:-/var/lib/witnessory-probe}"
USER_NAME="witnessory-probe"
UNIT="/etc/systemd/system/witnessory-probe.service"

say() { printf '%s\n' "$*"; }
die() { printf 'witnessory-probe install: %s\n' "$*" >&2; exit 1; }
as_probe() { runuser -u "$USER_NAME" -- "$@" 2>/dev/null || su -s /bin/sh "$USER_NAME" -c "$(printf "'%s' " "$@")"; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo sh install.sh)"

if [ "${1:-}" = "--uninstall" ] || [ "${1:-}" = "--purge" ]; then
  if command -v systemctl >/dev/null 2>&1 && [ -f "$UNIT" ]; then
    systemctl disable --now witnessory-probe.service >/dev/null 2>&1 || true
    rm -f "$UNIT"
    systemctl daemon-reload
  fi
  rm -rf "$PREFIX"
  if [ "$1" = "--purge" ]; then
    rm -rf "$PROBE_HOME"
    userdel "$USER_NAME" 2>/dev/null || true
    say "Witnessory probe removed, with its keys and results."
  else
    say "Witnessory probe removed. Its keys and results are kept in $PROBE_HOME (remove with --purge)."
  fi
  exit 0
fi

command -v python3 >/dev/null 2>&1 || die "Python 3.10 or newer is needed (for example: apt install python3 python3-venv)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || die "Python 3.10 or newer is needed"
python3 -c 'import venv, ensurepip' 2>/dev/null || die "Python's venv module is missing (for example: apt install python3-venv)"

if ! id "$USER_NAME" >/dev/null 2>&1; then
  useradd --system --home-dir "$PROBE_HOME" --shell /usr/sbin/nologin "$USER_NAME" 2>/dev/null \
    || useradd --system --home-dir "$PROBE_HOME" --shell /sbin/nologin "$USER_NAME"
fi
install -d -o "$USER_NAME" -g "$(id -gn "$USER_NAME")" -m 750 "$PROBE_HOME"

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
  systemctl daemon-reload
  systemctl enable --now witnessory-probe.service >/dev/null
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
