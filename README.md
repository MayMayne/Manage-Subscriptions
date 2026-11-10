# Sandbox

<p align="center">
  <img src="https://img.shields.io/badge/Platform-iOS%2015.0+-blue.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Swift-5.0-orange.svg" alt="Swift">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

<p align="center">
  <b>A simple iOS app for managing Sandbox settings and subscriptions.</b>
</p>

---

## 📱 Screenshots

| Light Mode | Dark Mode |
|:----------:|:---------:|
| <img width="1136" height="2168" alt="CleanShot 2026-01-13 at 19 13 12@2x" src="https://github.com/user-attachments/assets/07126c56-8465-49f0-8ed4-21f5cfbe8565" /> | <img width="1136" height="2168" alt="CleanShot 2026-01-13 at 19 13 47@2x" src="https://github.com/user-attachments/assets/e414458a-c385-49a5-9043-5a3b352bf302" /> |

---

## ✨ Features

- **🔧 Sandbox Settings** - Quick access to app settings
- **💳 Manage Sandbox Subscriptions** - View and manage in-app subscriptions via StoreKit
- **🛍️ Manage App Store Subscriptions** - Opens App Store subscription management externally
- **🔓 Sandbox Inspector** (iOS 26/27) - Reads StoreKit receipts and transaction stores
  inside other apps' containers with the `worse_query` sandbox escape: sandbox
  subscriptions, a container file browser and exploit diagnostics. See
  [WORSE_QUERY.md](WORSE_QUERY.md).

---

## 🛠️ Requirements

- iOS 15.0+ (the Sandbox Inspector needs iOS 26.0–26.7.2 or 27.0–27.2.x)
- Xcode 14.0+
- Swift 5.0+
- An **App Groups** entitlement — `worse_query` cannot issue a sandbox extension
  without one. Sideload tools that strip entitlements will disable the inspector.

---

## 📥 Unsigned IPA

`.github/workflows/build-unsigned-ipa.yml` builds a release IPA on a macOS runner and
re-signs it with `ldid` so the App Group entitlement survives:

```bash
gh workflow run build-unsigned-ipa.yml
```

Install the artifact with TrollStore (keeps entitlements), or with Sideloadly /
AltStore if your certificate includes the App Group capability.

---

## 📦 Installation

1. Clone this repository:
```bash
git clone https://github.com/thanhdo1110/Manage-Subscriptions.git
```

2. Open `sandbox.xcodeproj` in Xcode

3. Build and run on your device or simulator

---

## 🌍 Localization

The app supports the following languages:

| Language | Status |
|:---------|:------:|
| 🇻🇳 Vietnamese | ✅ |
| 🇺🇸 English | ✅ |

---

## 📂 Project Structure

```
sandbox/
├── sandbox/
│   ├── Assets.xcassets/          # App icons and colors
│   ├── Resources/
│   │   └── Localization/
│   │       ├── en.lproj/         # English strings
│   │       └── vi.lproj/         # Vietnamese strings
│   ├── ContentView.swift         # Main UI
│   └── sandboxApp.swift          # App entry point
└── sandbox.xcodeproj/
```

---

## 🎨 UI Design

The app follows **Apple iOS Settings** design guidelines:

- Clean, minimal interface
- App header with icon and description
- Grouped list sections with headers and footers
- Native iOS styling with `InsetGroupedListStyle`

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## TestFlight
• SANDBOX [CTDO](https://testflight.apple.com/join/jH3StjJu)
  
## 👨‍💻 Author

**ctdoteam**

- Website: [ctdo.net](https://ctdo.net)

---

<p align="center">
  Made with ❤️ by ctdoteam
</p>
