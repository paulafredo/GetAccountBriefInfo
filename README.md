# GetAccountBriefInfo

A lightweight MITMProxy addon that intercepts login requests, extracts UIDs from protobuf payloads, validates them against a local list, and rewrites server responses for invalid users.



## 🚀 Features

- UID validation from `uid.txt`  
- Protobuf decoding & encoding  
- Custom response injection for invalid UIDs  
- Nickname modification with error message  
- Automatic MITMProxy certificate export  
- Clean and minimal interceptor class



## 🖼️ Screenshot
![Demo Screenshot](https://github.com/paulafredo/GetAccountBriefInfo/blob/main/picture/screenshoots.png?raw=true)
---

## ⚙️ Installation

```bash
pip install mitmproxy protobuf
```
Place your valid UIDs inside:
```
uid.txt
```
▶️ Usage

Run the proxy:
```
mitmweb -s interceptor.py -p 8080 --set block_global=false
```
The MITM certificate will automatically be saved to:
```
certificat_mitmproxy.pe
```

## ⚠️ Disclaimer

This project is for educational and debugging purposes only.

## Author

[Paul Alfredo](https://github.com/paulafredo)
