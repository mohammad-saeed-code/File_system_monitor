# File_system_monitor
A lightweight GUI tool to monitor files/directories for changes and send notifications.
Built with **watchdog** + **PySimpleGUI**.

## Features
- Monitor files and directories (non-recursive directory watch)
- Detect changes on:
  - file name (limited by how OS reports events)
  - file size
  - permissions (human-readable mode)
  - content hash (MD5)
- Log events to `logging.txt` and keep an in-memory log list in the UI
- Desktop notifications on Linux via `notify-send`
- Email notifications via SMTP (Gmail supported)

## Screens / UI
- Left panel: monitored items
- Right panel: log entries
- Buttons: Add / Remove / Change Permissions / Start / Stop / Test Notification

## Requirements
- Python 3.10+ recommended
- Linux recommended (for `pwd` + `notify-send`)
- Packages:
  - watchdog
  - PySimpleGUI

## Install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
