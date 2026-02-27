# 🛡️ Typosquat Shield

> A Chrome extension that detects lookalike domains, typosquatting attacks, and phishing sites in real time — before you get scammed.

![Version](https://img.shields.io/badge/version-1.0.0-00e5a0?style=flat-square)
![Manifest](https://img.shields.io/badge/manifest-v3-00e5a0?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)

---

## 🚨 What is Typosquatting?

Attackers register domains like `arnazon.com` or `paypa1.com` — visually identical to trusted sites. When you accidentally visit one, they steal your passwords, payment info, and personal data.

**Typosquat Shield stops this before it happens.**

---

## ✨ Features

| Feature | Description |
|---|---|
| 📏 **Levenshtein Detection** | Catches domains 1–3 characters away from 50+ trusted sites |
| 🔡 **Homoglyph Detection** | Spots Unicode spoofing (Cyrillic `а` vs Latin `a`) |
| 🔬 **VirusTotal Integration** | Cross-checks against 70+ antivirus engines |
| 📅 **Domain Age Check** | Flags newly registered domains via RDAP |
| 🖱️ **Right-Click Link Checker** | Inspect any link before clicking |
| 📊 **Threat Dashboard** | Full history of all blocked threats |
| ✅ **Whitelist Manager** | Trust domains you know are safe |

---

## 🖥️ Screenshots

### Warning Page
When a suspicious domain is detected, you're redirected here before the page loads:

> *(Add screenshot here)*

### Dashboard
Full threat history with detection source, VirusTotal results, and domain age:

> *(Add screenshot here)*

### Popup
Quick status view with live threat stats:

> *(Add screenshot here)*

---

## 🚀 Installation (Developer Mode)

1. **Clone this repo**
   ```bash
   git clone https://github.com/YOUR_USERNAME/typosquat-shield.git
   cd typosquat-shield
   ```

2. **Open Chrome Extensions**
   - Go to `chrome://extensions/`
   - Enable **Developer Mode** (top right toggle)

3. **Load the extension**
   - Click **"Load unpacked"**
   - Select the `typosquat-shield/` folder

4. **Add your VirusTotal API key** *(optional but recommended)*
   - Sign up free at [virustotal.com](https://www.virustotal.com)
   - Go to Profile → API Key → Copy
   - Open `background.js` and paste it at line 12:
     ```javascript
     const VT_API_KEY = 'your_key_here';
     ```
   - Reload the extension

---

## 📁 Project Structure

```
typosquat-shield/
├── manifest.json       ← Extension config (Manifest V3)
├── background.js       ← Core detection engine (service worker)
├── content.js          ← Page-level monitor
├── popup.html/js       ← Extension popup UI
├── warning.html/js     ← Threat warning page
├── dashboard.html/js   ← Statistics dashboard
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## ⚙️ How It Works

When you navigate to any URL, the extension runs **three checks in parallel**:

```
URL entered
    │
    ├── 1. Levenshtein Check
    │       Compare domain against 50+ trusted domains
    │       Flag if edit distance ≤ 3
    │
    ├── 2. VirusTotal API
    │       Query 70+ security engines
    │       Flag if malicious/suspicious
    │
    └── 3. RDAP Domain Age
            Check registration date
            Flag if < 30 days old + other signals
                │
                ▼
        Threat? → Redirect to Warning Page
        Safe?   → Allow navigation
```

---

## 🔧 Configuration

Open `background.js` to adjust these settings:

```javascript
// Your VirusTotal API key (free at virustotal.com)
const VT_API_KEY = '';

// Max character edits to flag (2 = strict, 3 = balanced, 4 = sensitive)
const LEVENSHTEIN_THRESHOLD = 3;
```

---

## 🛡️ Trusted Domains List

The extension checks against 50+ commonly impersonated domains including:

Google, Gmail, YouTube, Facebook, Instagram, Twitter, Amazon, eBay, PayPal, Apple, Microsoft, GitHub, LinkedIn, Netflix, Spotify, Discord, Coinbase, Binance, Chase, Bank of America, and more.

To add your own trusted domains, edit the `TRUSTED_DOMAINS` array in `background.js`.

---

## 🔮 Roadmap

- [ ] ML-based scoring using phishing datasets
- [ ] Visual similarity detection (logo/color matching)
- [ ] SSL certificate age analysis
- [ ] Firefox support (Manifest V3 compatible)
- [ ] Export/import whitelist
- [ ] Chrome Web Store release

---

## 📄 Privacy Policy

- We do **not** collect your personal information
- We do **not** sell or share your browsing data
- Domain names (not full URLs) are sent to VirusTotal for threat analysis
- All other data (whitelist, history) is stored **locally in your browser only**

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙌 Contributing

Pull requests are welcome! For major changes, please open an issue first.

1. Fork the repo
2. Create your branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add my feature'`
4. Push: `git push origin feature/my-feature`
5. Open a Pull Request

---

Built with ❤️ to make the web a safer place.
