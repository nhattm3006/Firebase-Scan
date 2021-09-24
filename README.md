# FirebaseScan
```
_____ _          _                    _____                 
|  _|(_)        | |                  /  ___|                
| |_  _ _ __ ___| |__   __ _ ___  ___\ `--.  ___ __ _ _ ___ 
|  _|| | '__/ _ \ '_ \ / _` / __|/ _ \`--. \/ __/ _` | '_  \
| |  | | | |  __/ |_) | (_| \__ \  __/\__/ / (_| (_| | | | |
\_|  |_|_|  \___|_.__/ \__,_|___/\___\____/ \___\__,_|_| |_|

                 by: IAMABEAR of SunCSR team
```
FirebaseScan is a pen-testing tool to automatically scanning and exploiting Firebase DB vulnerability in the android application.

[![python](https://img.shields.io/badge/python-3-blue.svg?logo=python&labelColor=yellow)](https://www.python.org/downloads/)
[![platform](https://img.shields.io/badge/platform-linux%2Fwindows-green.svg)](https://github.com/NhatTranMinh99/Firebase-Scan/)

FirebaseScan is also bundled with [apktool](https://github.com/iBotPeaches/Apktool).

# Requirements
- Python 3
  - tqdm
  - requests
- JDK 8 or higher

# Feature
- Decode apk file
- Find Firebase Database URL
- Scan for configuration error on reading and writing permission
- Dump database
- Export payload

# Installation
```python
python3 -m pip install -r requirements.txt
```

# Usage
Put apk file in the directory of firebase-scan.
```python
python3 firebase-scan.py example.apk
```
