<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0c0e1c,60:1f2138,100:2a2d4a&height=200&section=header&text=PKA+Decipher&fontSize=68&fontColor=e8dcc8&fontAlignY=55&animation=fadeIn" width="100%"/>

<br/>

[![Python](https://img.shields.io/badge/Python-3.10+-e8dcc8?style=for-the-badge&logo=python&logoColor=1a1c2a)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows-5e6478?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/strykey/pka-decipher)
[![License](https://img.shields.io/badge/License-CUSTOM-7ec8a0?style=for-the-badge&logo=opensourceinitiative&logoColor=1a1c2a)](./LICENSE)
[![pywebview](https://img.shields.io/badge/pywebview-6.x-e8dcc8?style=for-the-badge&logo=python&logoColor=1a1c2a)](https://pywebview.flowrl.com)
[![Twofish](https://img.shields.io/badge/Crypto-Twofish%2FEAX-7ec8a0?style=for-the-badge&logo=gnuprivacyguard&logoColor=1a1c2a)](https://en.wikipedia.org/wiki/Twofish)

<br/>

*Decrypt, inspect, patch and re-encrypt Cisco Packet Tracer .pka / .pkt files. Full crypto stack implemented from scratch.*

<br/>

[What is this](#what-is-this) &nbsp;·&nbsp; [How it works](#how-it-works) &nbsp;·&nbsp; [Crypto stack](#crypto-stack) &nbsp;·&nbsp; [Project structure](#project-structure) &nbsp;·&nbsp; [Installation](#installation) &nbsp;·&nbsp; [Usage](#usage) &nbsp;·&nbsp; [License](#license)

</div>

<br/>

## What is this

PKA Decipher is a desktop tool that lets you open a Cisco Packet Tracer `.pka` or `.pkt` file, read the raw XML payload hidden inside, apply patches to it, and write it back to disk as a perfectly valid encrypted file that Packet Tracer will open without complaining.

The main application is **PKA_DECIPHER.py**, a full-featured editor with an XML viewer, live stats and a whole library of patch presets. Alongside it lives **PATCHER.py**, which is an intentionally simple example that demonstrates exactly how to use the `Decipher/` library to build your own patcher from scratch. It implements one specific patch — making the activity start already at 100% by replacing the COMPARISONS block — and shows the complete decrypt / modify XML / re-encrypt cycle in the most straightforward way possible. If you want to write your own tool on top of this crypto stack, PATCHER.py is the reference to read first.

The entire cryptographic pipeline — Twofish block cipher, CTR mode, CMAC authentication, EAX authenticated encryption — is implemented in pure Python, from scratch, with zero third-party crypto dependencies. Because why not.

> **Disclaimer:** This project is provided for educational and research purposes only. It was built to understand how Packet Tracer formats its files. The author is not responsible for any misuse. Use it on your own files.

<br/>

## How it works

Packet Tracer files are not stored as plain XML. There is a full encryption and obfuscation pipeline applied to the data before it hits the disk, and PKA Decipher reverses that pipeline entirely. Here is what happens to your file from raw bytes to readable XML and back, step by step.

**Reading a .pka file (decryption)**

The first thing that runs is a deobfuscation step called Stage 1. It reverses the byte order of the entire buffer and XORs each byte with a value derived from its position and the total length of the file. This is not real encryption, it is more like a light scramble to make the bytes look random at first glance. Once undone, the actual encrypted payload is revealed.

That payload is decrypted using EAX mode. EAX is an authenticated encryption scheme, meaning it both decrypts and verifies the integrity of the data in a single pass. It uses a fixed 128-bit Twofish key (all bytes set to 137) and a fixed 128-bit nonce (all bytes set to 16). The last 16 bytes of the Stage 1 output are the authentication tag, everything before that is the ciphertext.

After decryption, a second deobfuscation pass called Stage 2 is applied. This one XORs each byte with `(length - index) & 0xFF`, a simple rolling mask.

The result of all that is a Qt-compressed blob. It starts with a 4-byte big-endian integer that encodes the original uncompressed size, followed by raw zlib-compressed data. Decompress that and you get the XML.

**Writing a .pka file (re-encryption)**

The process runs exactly in reverse. The patched XML is encoded to latin-1, Qt-compressed (size prefix + zlib), Stage 2 obfuscated, EAX encrypted with Twofish, and Stage 1 obfuscated. The result is written atomically to disk via a `.tmp` file that is then renamed over the original, so if anything fails midway your file is not corrupted.

<br/>

## Crypto stack

The entire cryptographic layer lives in the `Decipher/` folder and is implemented from scratch in pure Python. Here is what each file does.

**twofish.py** is a full Python implementation of the Twofish symmetric block cipher. Twofish operates on 128-bit blocks and supports key sizes of 128, 192 and 256 bits. It uses a Feistel network with four rounds of MDS matrix multiplication, PHT transforms, and key-dependent S-boxes built from RS matrix operations and the q0/q1 lookup tables. Packet Tracer uses a 128-bit all-137 key. This file does the heavy lifting, it is the actual encryption primitive that everything else is built on top of.

**cmac.py** implements CMAC (Cipher-based Message Authentication Code) on top of any block cipher. It generates two subkeys K1 and K2 by encrypting a zero block and applying a GF(2^128) left shift with conditional XOR against the constant 0x87 (the irreducible polynomial for that field). It then processes the message in 16-byte blocks, handling padding for incomplete last blocks, and produces a 16-byte authentication tag. CMAC is used internally by EAX to authenticate the nonce, the associated data and the ciphertext separately.

**ctr.py** implements CTR (Counter) mode for stream encryption. It takes any block cipher, a 128-bit initial counter value, and encrypts successive counter values to produce a keystream. The counter is incremented in big-endian order after each block, exactly like Crypto++ does it. XORing the keystream against the plaintext gives the ciphertext, and since XOR is its own inverse, the exact same operation decrypts. CTR mode turns a block cipher into a stream cipher and never needs padding.

**eax.py** puts CMAC and CTR together to implement EAX authenticated encryption. The scheme works like this: it computes OMAC_0 (CMAC of a 16-byte prefix 0x00 concatenated with the nonce) to derive the CTR starting counter, OMAC_1 (CMAC of prefix 0x01 concatenated with the associated additional data) to authenticate the header, and OMAC_2 (CMAC of prefix 0x02 concatenated with the ciphertext) to authenticate the encrypted body. The final authentication tag is the XOR of all three OMAC outputs. On decryption, the tag is recomputed and compared to the one provided. If they do not match it throws a ValueError and the file is not written.

**pt_crypto.py** is the glue layer that wires all of the above together specifically for Packet Tracer files. It implements the two deobfuscation functions (Stage 1 and Stage 2), the Qt decompression wrapper, and the main `decrypt_pkt` function that takes raw `.pka` bytes and returns the decoded XML string. This is the only file you need to call from the outside if you want to integrate the decryption into your own script.

<br/>

## Project structure

```
pka-decipher/
├── PKA_DECIPHER.py       # Full desktop editor with XML viewer, presets, live stats
├── PATCHER.py            # Example patcher: shows how to use Decipher/ to build your own tool
├── Decipher/
│   ├── twofish.py        # Twofish 128-bit block cipher, pure Python
│   ├── cmac.py           # CMAC message authentication code
│   ├── ctr.py            # CTR stream mode
│   ├── eax.py            # EAX authenticated encryption (CTR + CMAC)
│   └── pt_crypto.py      # Packet Tracer specific crypto pipeline
├── icon.ico / icon.png   # App icon (optional)
└── README.md             # You are here
```

<br/>

## Installation

```bash
git clone https://github.com/strykey/pka-decipher.git
cd pka-decipher
pip install pywebview pillow
```

That is it. No extra crypto libraries. The entire Twofish/EAX/CMAC/CTR stack ships with the project.

**Requirements**

```
Python    >= 3.10
pywebview >= 6.0
pillow              (optional, for icon conversion on Windows)
```

<br/>

## Usage

**PKA Decipher** is the full tool. Run it with:

```bash
python PKA_DECIPHER.py
```

A window opens with a three-panel layout. The left sidebar shows all the available patch presets organized into categories. The center panel is a virtualized XML viewer that can display tens of thousands of lines without freezing, with a live search bar that highlights matches and lets you jump between them with arrow buttons. The right sidebar shows live stats about the currently loaded file: number of verification nodes, average score, device count, active timers, locks, and passwords found.

To use it, click the file picker, select your `.pka` or `.pkt` file, wait a second for it to decrypt and load, then pick any combination of presets from the left panel and click Apply. Each preset logs exactly what it changed. When you are done, click Save and the file is re-encrypted and written back to disk.

**PATCHER.py** is an example script that shows how to use the `Decipher/` library to build a custom patcher. The patch it implements specifically makes the activity register as already completed at 100% on launch: it replaces the entire COMPARISONS block in the XML with a single always-true verification node worth 100 points, so Packet Tracer considers the activity done from the moment it opens. Run it with:

```bash
python PATCHER.py
```

A small card-style window opens, you pick your file, you click Inject, done. The progress bar walks through each step live: reading, decrypting Twofish/EAX, patching the COMPARISONS block, re-encrypting, writing back to disk. The file is replaced atomically so nothing is corrupted if something goes wrong midway.

This file is also the cleanest way to understand how to wire the `Decipher/` crypto stack into your own script. The pipeline is: `decrypt_pkt` to get the XML, modify the string however you want, then `xml_to_pka` to get back the encrypted bytes ready to write to disk. That is the whole API.

<br/>

## Patch presets

PKA Decipher ships with a full set of presets that can be applied individually or combined in any order.

**100% Completion** strips all verification nodes from the COMPARISONS block and replaces them with a single always-true node worth 100 points. This makes the activity register as already completed at 100% the moment it is opened in Packet Tracer. This is also the exact patch that PATCHER.py demonstrates as a usage example of the crypto library.

**God Score** sets every POINTS node in the file to 100. Good for when the activity uses a weighted scoring system that the previous preset alone does not fully cover.

**Zero Score Threshold** sets every PASS_SCORE, passScore attribute and MIN_SCORE field to 0, meaning any score passes. Useful when you need the activity to consider you done without touching the actual scoring logic.

**Unlock All** removes every `locked="true"`, `<LOCKED>true</LOCKED>`, `lock="1"` and `<LOCK>1</LOCK>` flag in the file. If a device or component was locked in the activity so students could not modify it, it is now unlocked.

**Bypass Timer** disables every TIME_LIMIT, sets TIMER_ENABLED to false wherever it appears, and zeros out TIME fields. The clock stops.

**Show Answers** flips every `showAnswers="false"` and `answersVisible="false"` flag to true. Some activities hide expected configurations or answers until a certain score is reached, this makes them all visible immediately.

**Max Attempts** sets every `maxAttempts`, `MAX_ATTEMPTS` and `ATTEMPTS_LIMIT` field to 999. Packet Tracer sometimes limits how many times you can submit or check, this effectively removes that limit.

**Enable Hints** turns on hints everywhere they were disabled.

**Remove Feedback** clears all `incorrectFeedback` messages. Cosmetic mostly, but useful if you want a clean activity.

**Unlock Activity Wizard** clears every activity password and wizard password stored in the file.

**Strip Device Passwords** clears all SECRET, ENABLE_SECRET, ENABLE_PASSWORD, VTY_PASSWORD and CON_PASSWORD fields on every device in the topology.

**Enable All Ports** sets every `portEnabled="false"`, `<SHUTDOWN>true</SHUTDOWN>` and `shutdown="true"` flag to their enabled counterpart. Brings up every interface that was administratively shut down in the activity definition.

There are also presets for interfaces, VLAN visibility, OSPF/BGP configuration visibility, CDP/LLDP, STP settings, QoS, ACLs, NAT, DHCP leases and a handful of other topology-level fields. The full list is in the left sidebar when you open the app.

<br/>

## License

Custom. Check it.

<br/>

<div align="center">

<br/>

made with love by **Strykey**

<br/>

[![GitHub stars](https://img.shields.io/github/stars/strykey/pka-decipher?style=for-the-badge&color=e8dcc8&labelColor=1a1c2a)](https://github.com/strykey/pka-decipher/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/strykey/pka-decipher?style=for-the-badge&color=e8dcc8&labelColor=1a1c2a)](https://github.com/strykey/pka-decipher/network)

<br/>

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:2a2d4a,60:1f2138,100:0c0e1c&height=120&section=footer" width="100%"/>

</div>
