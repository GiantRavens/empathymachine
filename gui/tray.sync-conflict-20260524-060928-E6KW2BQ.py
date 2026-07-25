#!/usr/bin/env python3
"""EmpathyMachine menu-bar / system-tray app.

Cross-platform via pystray:
  - macOS: NSStatusItem
  - Linux GNOME family: AppIndicator (requires gnome-shell-extension-appindicator
    on pure GNOME; ships by default on Cinnamon/Pantheon/KDE/Pop_OS!)

Self-contained: lives in ~/.empathymachine/ on macOS to dodge the TCC
restriction on LaunchAgents exec'ing under ~/Desktop. Reads no files
from the project tree at runtime — talks to:
  - http://127.0.0.1:8081/api/*    for state and metrics
  - ~/.empathymachine/proxy-desired.txt + em-proxy-reapply   for proxy toggle
  - launchctl / systemctl --user   for service control
  - webbrowser.open                for dashboard / source links
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

from PIL import Image, ImageDraw

# pystray grabs the X display / NSStatusBar at import time, which fails on
# headless or SSH sessions. Import lazily inside main() so the rest of this
# module (icons, state, polling) can be unit-tested without a display.

# ─── config ──────────────────────────────────────────────────────────────

ADMIN_URL = os.environ.get("EMPATHYMACHINE_ADMIN_URL", "http://127.0.0.1:8081")
POLL_INTERVAL_SEC = 5
EM_HOME = Path.home() / ".empathymachine"
PROXY_DESIRED_FILE = EM_HOME / "proxy-desired.txt"
PROXY_REAPPLY_SCRIPT = EM_HOME / "em-proxy-reapply"
SERVICE_LABEL = "com.giantravens.empathymachine"
SYSTEMD_UNIT = "empathymachine.service"
IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

# ─── icon rendering ──────────────────────────────────────────────────────

def _make_icon(color: tuple[int, int, int], glyph: str = "") -> Image.Image:
    """Generate a 22x22 PNG icon (template-sized for Mac menu bar)."""
    size = 22
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # Solid circle in the requested color
    d.ellipse((3, 3, size - 3, size - 3), fill=(*color, 255))
    # Outline for visibility on light + dark menubar
    d.ellipse((3, 3, size - 3, size - 3), outline=(0, 0, 0, 220), width=1)
    if glyph:
        d.text((size // 2 - 3, size // 2 - 6), glyph, fill=(255, 255, 255, 255))
    return img


ICON_RUNNING_ON = _make_icon((40, 180, 80))      # green = service up + proxy routing
ICON_RUNNING_OFF = _make_icon((220, 180, 60))    # amber = service up, proxy off
ICON_STOPPED = _make_icon((200, 60, 60), "×")    # red = service down


# ─── state polling ───────────────────────────────────────────────────────

class State:
    def __init__(self) -> None:
        self.service_running: bool = False
        self.proxy_desired: str = "off"
        self.uptime_s: int = 0
        self.version: str = "?"
        self.requests: int = 0
        self.allowed: int = 0
        self.blocked: int = 0
        self.rewritten: int = 0
        self.error: int = 0
        self.last_poll_error: str | None = None

    def icon(self) -> Image.Image:
        if not self.service_running:
            return ICON_STOPPED
        if self.proxy_desired == "on":
            return ICON_RUNNING_ON
        return ICON_RUNNING_OFF

    def header_label(self) -> str:
        ver = f"v{self.version}" if self.version != "?" else "?"
        if not self.service_running:
            return f"EmpathyMachine — STOPPED"
        uptime = _fmt_uptime(self.uptime_s)
        return f"EmpathyMachine {ver} — up {uptime}"

    def metrics_label(self) -> str:
        if not self.service_running:
            return self.last_poll_error or "(service not reachable)"
        pct = (self.blocked * 100.0 / self.requests) if self.requests else 0
        return f"Reqs {self.requests} • Blocked {self.blocked} ({pct:.1f}%) • Rewritten {self.rewritten}"


def _fmt_uptime(s: int) -> str:
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60}m"
    d = s // 86400
    return f"{d}d {(s % 86400) // 3600}h"


def _fetch_json(path: str, timeout: float = 1.5) -> dict | None:
    try:
        with urllib.request.urlopen(f"{ADMIN_URL}{path}", timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError):
        return None
    except Exception:
        return None


def _read_proxy_desired() -> str:
    try:
        return PROXY_DESIRED_FILE.read_text().strip() or "off"
    except FileNotFoundError:
        return "off"
    except Exception:
        return "off"


def poll_state(state: State) -> bool:
    """Returns True if state changed enough to warrant a redraw."""
    prev_icon = state.icon()
    prev_metrics = state.metrics_label()
    status = _fetch_json("/api/status")
    metrics = _fetch_json("/api/metrics") if status else None

    if status:
        state.service_running = True
        state.uptime_s = int(status.get("uptime_seconds", 0))
        state.version = status.get("version", "?")
        state.last_poll_error = None
    else:
        state.service_running = False
        state.last_poll_error = "(admin API not reachable)"

    if metrics:
        totals = metrics.get("totals", {})
        state.requests = int(totals.get("requests", 0))
        state.allowed = int(totals.get("allowed", 0))
        state.blocked = int(totals.get("blocked", 0))
        state.rewritten = int(totals.get("rewritten", 0))
        state.error = int(totals.get("error", 0))

    state.proxy_desired = _read_proxy_desired()
    return prev_icon != state.icon() or prev_metrics != state.metrics_label()


# ─── actions ─────────────────────────────────────────────────────────────

def _set_proxy_desired(value: str) -> None:
    EM_HOME.mkdir(parents=True, exist_ok=True)
    PROXY_DESIRED_FILE.write_text(value + "\n")


def _run(cmd: list[str]) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {e}"


def action_proxy_on(_icon, _item) -> None:
    _set_proxy_desired("on")
    if IS_MAC and PROXY_REAPPLY_SCRIPT.exists():
        _run([str(PROXY_REAPPLY_SCRIPT)])
    elif IS_LINUX:
        # gsettings is the actual on-disk state; we set it directly here
        # rather than shelling to the launcher (which is under ~/Desktop).
        _run(["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"])
        _run(["gsettings", "set", "org.gnome.system.proxy.http", "host", "127.0.0.1"])
        _run(["gsettings", "set", "org.gnome.system.proxy.http", "port", "8080"])
        _run(["gsettings", "set", "org.gnome.system.proxy.https", "host", "127.0.0.1"])
        _run(["gsettings", "set", "org.gnome.system.proxy.https", "port", "8080"])


def action_proxy_off(_icon, _item) -> None:
    _set_proxy_desired("off")
    if IS_MAC and PROXY_REAPPLY_SCRIPT.exists():
        _run([str(PROXY_REAPPLY_SCRIPT)])
    elif IS_LINUX:
        _run(["gsettings", "set", "org.gnome.system.proxy", "mode", "none"])


def action_service_start(_icon, _item) -> None:
    if IS_MAC:
        plist = Path.home() / "Library/LaunchAgents" / f"{SERVICE_LABEL}.plist"
        if plist.exists():
            _run(["launchctl", "load", "-w", str(plist)])
    elif IS_LINUX:
        _run(["systemctl", "--user", "start", SYSTEMD_UNIT])


def action_service_stop(_icon, _item) -> None:
    if IS_MAC:
        plist = Path.home() / "Library/LaunchAgents" / f"{SERVICE_LABEL}.plist"
        if plist.exists():
            _run(["launchctl", "unload", str(plist)])
    elif IS_LINUX:
        _run(["systemctl", "--user", "stop", SYSTEMD_UNIT])


def action_service_restart(_icon, _item) -> None:
    if IS_MAC:
        _run(["launchctl", "kickstart", "-k", f"gui/{os.getuid()}/{SERVICE_LABEL}"])
    elif IS_LINUX:
        _run(["systemctl", "--user", "restart", SYSTEMD_UNIT])


def action_open_dashboard(_icon, _item) -> None:
    webbrowser.open(ADMIN_URL)


def action_quit(icon, _item) -> None:
    icon.stop()


# ─── menu ────────────────────────────────────────────────────────────────

def build_menu(state: State):
    import pystray
    return pystray.Menu(
        pystray.MenuItem(state.header_label(), None, enabled=False),
        pystray.MenuItem(state.metrics_label(), None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            "Proxy: System Routing",
            action_proxy_on if state.proxy_desired != "on" else action_proxy_off,
            checked=lambda _: state.proxy_desired == "on",
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            "Start Service",
            action_service_start,
            visible=not state.service_running,
        ),
        pystray.MenuItem(
            "Stop Service",
            action_service_stop,
            visible=state.service_running,
        ),
        pystray.MenuItem(
            "Restart Service",
            action_service_restart,
            visible=state.service_running,
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Open Dashboard…", action_open_dashboard),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit Tray", action_quit),
    )


# ─── main loop ───────────────────────────────────────────────────────────

def _poller(icon, state: State) -> None:
    while True:
        try:
            changed = poll_state(state)
        except Exception:
            changed = True
        # Always re-render — uptime ticks each poll, and the menu shows it.
        icon.icon = state.icon()
        icon.menu = build_menu(state)
        try:
            icon.update_menu()
        except Exception:
            pass
        time.sleep(POLL_INTERVAL_SEC)


def main() -> int:
    import pystray
    state = State()
    poll_state(state)

    icon = pystray.Icon(
        "empathymachine",
        icon=state.icon(),
        title="EmpathyMachine",
        menu=build_menu(state),
    )

    t = threading.Thread(target=_poller, args=(icon, state), daemon=True)
    t.start()

    try:
        icon.run()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
