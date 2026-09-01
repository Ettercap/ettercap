# GTK4 interface test harness

Automated smoke/regression coverage for the GTK4 + libadwaita interface
(`src/interfaces/gtk4/`). The GTK interface has historically only been
exercised by hand; the GTK3 → GTK4 port turned every dialog asynchronous
(GTK4 removed `gtk_dialog_run()`), which is exactly the kind of change that
introduces bugs a scripted pass catches immediately and a human notices late.

## What's here

| file | purpose |
|------|---------|
| `provision.sh` | Install deps and build the GTK4 interface. Plain shell, no Cua dependency — the single definition of "how to build this", shared by the harness, CI, and manual use. |
| `harness.py` | Drive the built binary in a [Cua](https://cua.ai) cloud sandbox: launch it, read its accessibility tree, assert, screenshot. |
| `fixtures/make_sample_pcap.py` | Generate `fixtures/sample.pcap` — a synthetic HTTP exchange with known contents, so the offline checks can assert on specific rows. |

## Requirements

- **Ubuntu 24.04 or newer.** The interface needs libadwaita ≥ 1.5
  (`AdwDialog`/`AdwAlertDialog`); 22.04 ships 1.1. `provision.sh` refuses to
  build on anything older.
- **Cua credentials** for the cloud harness: `CUA_CLIENT_ID`,
  `CUA_CLIENT_SECRET`, `CUA_POOL_NAME` (get them at https://cua.ai). The
  harness reads them from the environment — `source ~/.config/cua/env`.
- **uv** (`pacman -S uv` / `pipx install uv`). The Cua SDK caps at Python
  < 3.14; the inline script metadata in `harness.py` makes `uv run` fetch a
  compatible interpreter and the SDK automatically. There is no virtualenv
  to manage.

## Running

```sh
# build and drive in a fresh cloud sandbox
source ~/.config/cua/env
./tests/gtk4/harness.py

# keep the pool warm between runs (a rebuild is minutes; skip it next time)
./tests/gtk4/harness.py --keep
./tests/gtk4/harness.py --keep --skip-build   # reuses the warm build

# one check at a time
./tests/gtk4/harness.py --check shortcuts
```

Screenshots and accessibility dumps land in `build-gtk4-artifacts/`.

## Building locally without the harness

`provision.sh` works on any Ubuntu 24.04+ machine or container:

```sh
./tests/gtk4/provision.sh --source-dir . --build-dir build-gtk4
./tests/gtk4/provision.sh --build-only    # skip the apt step
```

It also grants `CAP_NET_RAW`/`CAP_NET_ADMIN` on the built binary so the GUI
can capture as an unprivileged user (which matters for the accessibility bus).
Offline mode (`ettercap -G -r some.pcap`) exercises most of the interface
without any capability at all.

## Checks

- **startup** — the main window appears; no GTK criticals logged.
- **shortcuts** — the shortcuts window is generated from the accelerator
  map (this replaced the 1372-line hand-written `ec_gtk3_shortcuts.c`).
- **dialogs** — each async dialog opens, answers, and frees its context;
  the app stays responsive afterwards (catches a response callback that
  never fires).
- **about** — the `AdwAboutDialog` opens.

GTK criticals are treated as failures: a critical from presenting a dialog
against a destroyed parent, or a `finish()` on an already-consumed `GTask`,
does not crash the process and does not show on screen — but it means the
async dialog plumbing is wrong. Desktop-environment noise (the sandbox's
Xfce theme, software-render DRI3 warnings) is filtered out; see
`CuaSandbox.IGNORED_LOG`.
