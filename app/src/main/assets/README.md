# App Assets

This directory contains bundled payload files shipped inside the APK.

## Required files

### profiles.json
The device profile feed. Maps each supported Pixel firmware to its asset paths.

### explores/*.so
Pre-compiled exploit payloads (CVE-2026-43499 APP_PAYLOAD variant) for each
target. Built from the payloads/ directory with:
```
make TARGET=frankel-CP2A.260605.012 ANDROID_NDK_HOME=...
```

The output `cve-2026-43499-app.release.so` goes into `app/src/main/assets/exploits/<target>.so`.

### ksud/ksud
The ReSukiSU late-load binary, downloaded from official ReSukiSU releases.

### companions/*.apk
Bundled companion APKs offered for one-tap install from the main screen
(system package installer, via the app's FileProvider):

- `shizuku-v13.6.0.apk` — upstream release v13.6.0
  (github.com/RikkaApps/Shizuku, Apache-2.0), SHA-256
  `25657BC449439687608FFFA04B4B586DE90FC405E3DC6217BD997FC71BA0A0A1`
- `resukisu-v4.2.0-rc3-arm64.apk` — ReSukiSU v4.2.0-rc3 (35171) arm64-v8a
  manager (github.com/ReSukiSU/ReSukiSU, GPL-3.0; source at the same repo),
  SHA-256
  `6E273AB0E991C4E79BC8B1BBB9B9DD739CCAC1A8712A541A214078886B7B790F`


One binary covers every KMI. It embeds a `kernelsu.ko` per KMI (`android12-5.10`
through `android16-6.12`) and selects between them from the `--kmi` it is passed
at late-load, which is what a profile's `kmi` field supplies. This used to be
shipped as one file per KMI; those copies were byte-identical, so they were
merged into this one.

## Adding a new target

1. Add the target profile to `profiles.json`
2. Build the exploit .so for that target via the payloads/ Makefile
3. Copy the .so to `exploits/<profileId>.so`
4. Set the profile's `kmi` to the target's kernel KMI, so late-load picks the
   right `kernelsu.ko` out of `ksud/ksud`
