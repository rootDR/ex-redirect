# ex-redirect

**ex-redirect** is an automated tool that finds potential open redirect vulnerabilities by analyzing historical URLs from the [Wayback Machine](https://archive.org/web/). It supports subdomain grouping, live URL checking, and WordPress path filtering.

## 🚀 Features

- 🔍 Fetches archived URLs from the Wayback Machine
- 🌐 Scans both main domain and subdomains (wildcard support)
- 🧪 Filters potential open redirect parameters automatically
- ✅ Option to check if URLs are live
- 🚫 Option to ignore WordPress-related paths
- 📂 Saves results grouped by subdomain

## 🛠️ Usage

```bash
python ex-redirect.py -t example.com
```

### Options

| Option        | Description |
|---------------|-------------|
| `-t, --target` | Target domain (e.g., example.com) **[required]** |
| `-s, --subdomains` | Scan all subdomains (via Wayback wildcard) |
| `-l, --live` | Only save live open redirect URLs |
| `-wp, --wordpress` | Ignore WordPress-related paths |

### Example

```bash
python ex-redirect.py -t example.com -s -l -wp
```

## 📦 Installation

```bash
pip install -r requirements.txt
```

## 📁 Output

- Results are saved in a folder named after the target domain.
- Each file is named after the subdomain and contains the list of potential open redirect URLs.

## ✍️ Author

- 👨‍💻 rootdr
- 🐦 Twitter: [@R00TDR](https://twitter.com/R00TDR)
- 📡 Telegram: [RootDr](https://t.me/RootDr)

## ⚠️ Disclaimer

This tool is for **educational purposes** only. Usage of this tool for attacking targets without prior mutual consent is **illegal**.
