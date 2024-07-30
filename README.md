# authy-backup
A way to extract Authy TOTP tokens using a rooted Android device. Read the full blog post on: https://markuta.com/export-authy-backups/

## Demo
https://github.com/user-attachments/assets/d0bb8f59-9da7-405b-9eae-30dd76f91eac


## Requirements
Install the following Python modules, I'd also advise creating a virtual environment with `venv` to keep things organised:

```
python3 -m venv .venv
source .venv/bin/activate
pip3 install frida pyotp qrcode
```

## Usage
Ensure your rooted Android device is connected via USB and the Frida server is running as root.
```
python3 authy-offline.py
```
