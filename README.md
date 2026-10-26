# ScreenShare Forensic Scanner

A forensic scanner for **screenshare** sessions on **FiveM** and **Minecraft**, built to help moderators and staff detect advanced cheats (kernel, DMA, firmware/UEFI) and attempts to hide them.

This repository contains the signature database (`signatures.json`) and the documentation for using it in your scanner.

> **Note:** this is a defensive tool. Use it only on machines where you have explicit consent to perform the analysis (e.g. a screenshare the player has agreed to).

---

## What it detects

| Category | Description |
|---|---|
| `dma_hardware_pnp` | PCI/USB IDs, device names and typical anomalies of DMA cards (FPGA, FTDI, spoofed IDs) |
| `dma_software_artifacts` | Files, processes, DLLs and in-memory strings related to PCILeech, MemProcFS, LeechCore and DMA libraries |
| `input_emulation_hardware` | External hardware mice/keyboards (kmbox, Arduino, Pico, Teensy) and related software |
| `kernel_cheat_and_loaders` | Kernel mappers and loaders, vulnerable drivers (BYOVD), kernel artifacts, relevant Event IDs and registry keys |
| `firmware_uefi_smm_indicators` | **Indirect** indicators of firmware/UEFI/SMM tampering: flashing tools, Secure Boot, ESP, SMBIOS, TPM |
| `fivem_cheats` | Known menus/executors, suspicious natives and events, FiveM folders and files |
| `minecraft_cheats` | Cheat clients, modules, Java agents and injection, obfuscators, autoclickers and macros |
| `anti_bypass_and_evasion_detection` | Log and trace wiping, anti-screenshare, renamed or packed binaries, HWID spoofers |
| `system_state_checks` | Windows security posture and timeline/uptime checks |

---

## Structure

```
.
├── README.md
└── signatures.json
```

`signatures.json` is organized by category; each section contains lists of strings, paths, IDs or textual heuristics.

---

## Usage

1. Load `signatures.json` into your scanner.
2. Apply each category to the right data source:
   - **Processes and modules** → file names, DLLs, executables
   - **Memory of `javaw.exe` / `FiveM_*_GTAProcess.exe`** → in-memory strings
   - **Registry** → service keys, BAM, UserAssist, MuiCache, ShimCache
   - **Event Log** → the listed Event IDs
   - **PnP / PCI / USB** → device IDs
   - **Filesystem** → paths, Prefetch, Amcache, USN Journal
3. Assign a **weight** to each match and only flag results above a threshold to reduce false positives.
4. Correlate findings: a single match is rarely enough, several indicators together are.

### Example (Python)

```python
import json

with open("signatures.json", encoding="utf-8") as f:
    sigs = json.load(f)

def scan_text(text: str, strings: list[str]) -> list[str]:
    t = text.lower()
    return [s for s in strings if s.lower() in t]

hits = scan_text(process_list_dump, sigs["kernel_cheat_and_loaders"]["mappers_and_loaders"])
print(hits)
```

---

## Known limitations

- **SMM (ring -2) and UEFI implants are not visible from userland.** No string can prove their absence. The firmware category only contains indirect indicators; a proper check requires an SPI dump compared against the vendor's official firmware.
- **DMA leaves few traces on the gaming PC**, because the cheat runs on a second machine. The useful traces are hardware-related (PCI/USB devices, IOMMU, Kernel DMA Protection).
- **Strings are easy to evade** through renaming, recompiling and obfuscation. They should be combined with hashes, PE metadata, digital signatures, YARA rules and timeline analysis.
- **Cheat names change frequently:** the database needs regular updates.
- Some generic strings (`Speed`, `Fly`, `TriggerServerEvent`) can cause false positives if used on their own.
- The `VID_0403&PID_601E/601F/6010` (FTDI) and `DEV_0666` (PCILeech) IDs should be verified on real hardware before building a detection on them.

---

## Roadmap

- [ ] Convert signatures into YARA rules with scoring
- [ ] Automatic reading of registry, Prefetch, Amcache, BAM, USN Journal
- [ ] PnP/PCI/USB enumeration and IOMMU / Kernel DMA Protection checks
- [ ] Memory scanning of `javaw.exe` and `FiveM_*_GTAProcess.exe`
- [ ] Digital signature and `OriginalFilename` verification of binaries
- [ ] Final report (HTML/JSON) with risk score and timeline

---

## Contributing

Pull requests and issues are welcome: new signatures, false positives, corrections to IDs and names. Always include the source or explain how you verified the signature.

## Disclaimer

This tool is intended for moderation and security purposes. Using it on systems without authorization is prohibited. The scanner's output is an **indicator**, not definitive proof: every ban decision should be confirmed by a manual review.

## License

Choose the license you prefer (e.g. MIT) and add a `LICENSE` file.
