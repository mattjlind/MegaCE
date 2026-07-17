# MegaCE

MegaCE is an experimental MEGA client for Windows Mobile / Windows CE devices.
It is built with Visual Studio 2008 and targets Windows Mobile 6 Professional
SDK on ARMV4I devices.

The current focus is a small, usable mobile interface for:

- MEGA login with saved session support.
- Browsing MEGA files and folders.
- Downloading files.
- Uploading local files.
- Creating, renaming, and deleting MEGA folders/files.
- One-way and two-way sync against a configured local directory.

## Status

MegaCE is under active development. Core login, node browsing, file download,
file upload, and basic two-way sync are working, but the sync engine should
still be tested against disposable data before using it with important files.

## Runtime Dependency: BearTLS

MegaCE does not embed or install `wm_https.dll`.

TLS, PBKDF2-SHA512, RSA session decryption, and MEGA hashcash acceleration are
provided by the separate BearTLS runtime. BearTLS must be installed on the
device before MegaCE can connect to MEGA.

MegaCE searches for BearTLS `wm_https.dll` in this order:

1. `HKLM\Software\BearTLS\DllPath`
2. `\Program Files\BearTLS\wm_https.dll`
3. `\Storage Card\Program Files\BearTLS\wm_https.dll`
4. `\CF Card\Program Files\BearTLS\wm_https.dll`
5. `\SD Card\Program Files\BearTLS\wm_https.dll`

The BearTLS CAB writes the registry value during install. The fixed paths are
fallbacks for common device and storage-card install locations.

## Building

Requirements:

- Visual Studio 2008
- Windows Mobile 6 Professional SDK
- ARMV4I toolchain

Build the Release ARMV4I configuration:

```text
vcbuild.exe MegaCE\MegaCE.vcproj "Release|Windows Mobile 6 Professional SDK (ARMV4I)" /rebuild
```

The build outputs `MegaCE.exe`. It does not copy `wm_https.dll` into the output
directory; install BearTLS on the device instead.

## Local Files

MegaCE stores local runtime state beside the executable:

- `session.dat` - saved MEGA session
- `settings.dat` - app settings
- `syncstate.dat` - sync baseline state
- `log.txt` - saved log output, when requested

These files are intentionally ignored by Git.

## Notes

This is not an official MEGA client. It uses a small Windows Mobile UI and a
minimal MEGA API implementation tailored for legacy devices.
