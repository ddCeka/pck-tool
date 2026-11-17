# pckt

A fast, lightweight command-line tool written in C for inspecting, unpacking, and repacking Godot Engine `.pck` archives and self-contained game executables.

Designed for asset optimization and game modding workflows, `pckt` uses memory-mapped I/O (`mmap`) and chunked disk streaming so multi-gigabyte game archives can be unpacked or rebuilt with minimal RAM usage.

## Features

- **Format Support:** Reads and writes Godot PCK format versions **v1, v2, v3, and v4**.
- **Embedded Executables:** Unpacks directly from self-contained Windows (`.exe`), Linux, and macOS binaries, and bundles or replaces `.pck` payloads inside executables via `--embed`.
- **Metadata Matching:** Clones exact PCK format and Godot engine versions from existing archives or executables using `--copy-meta` or `--engine`.
- **Extension Filtering:** Inspect or extract specific asset types (such as `.ctex`, `.stex`, `.oggstr`, or `.oggvorbisstr`) using `--filter`.
- **Encrypted Archives:** Decrypts AES-256-CFB encrypted directories and files during `list` and `unpack` via `--key` or `--key-file`.
- **Low-Memory I/O & Deterministic Builds:** Uses read-only `mmap` for archive reading, 64 KB chunked file streaming for packing, deterministic alphabetical file sorting, and strict path traversal protection.

## Usage

```bash
pckt <list|unpack|pack> <in> [out] [options]
```

### Options

| Option | Modes | Description |
| :--- | :--- | :--- |
| `--filter <ext1,ext2,...>` | `list`, `unpack` | Only process files matching the comma-separated extensions (case-insensitive, leading dot optional). |
| `--key <64-hex>` | `list`, `unpack` | 64-character hexadecimal AES-256 decryption key. |
| `--key-file <path>` | `list`, `unpack` | Read the 64-character hex decryption key from a file. |
| `--v1` \| `--v2` \| `--v3` \| `--v4` | `pack` | Target PCK format version (default: `v3`). |
| `--engine <M.m.p>` | `pack` | Set the Godot engine version header (e.g., `4.3.0` or `3.5.3`). |
| `--copy-meta <pck\|exe>` | `pack` | Copy PCK format and engine version metadata from an original `.pck` or executable. |
| `--embed <exe>` | `pack` | Bundle the packed archive into a base executable (replaces any existing embedded `.pck`). |

### Examples

- **List archive contents sorted by size:**
  ```bash
  pckt list ./Game.pck
  ```
- **Inspect only compiled audio or texture assets:**
  ```bash
  pckt list ./Game.pck --filter .oggstr,.oggvorbisstr,.ctex
  ```
- **Unpack an archive or self-contained executable:**
  ```bash
  pckt unpack ./Game.exe ./game_files
  ```
- **Extract only audio streams for re-encoding (e.g., with `ffmpeg`):**
  ```bash
  pckt unpack ./Game.pck ./audio_only --filter oggstr,oggvorbisstr,sample
  ```
- **Unpack an encrypted archive:**
  ```bash
  pckt unpack ./Game.pck ./game_files --key-file ./godot.gdkey
  ```
- **Repack a directory matching the original game's format and Godot version:**
  ```bash
  pckt pack ./game_files ./Game_patched.pck --copy-meta ./Game.pck
  ```
- **Repack and re-embed directly into a game executable:**
  ```bash
  pckt pack ./game_files ./Game_patched.exe --copy-meta ./Game.exe --embed ./Game.exe
  ```

## Building & Testing

### Prerequisites

- A C11-compatible compiler (`gcc` or `clang`)
- GNU `make`
- OpenSSL development headers and `libcrypto` (`libssl-dev` on Debian/Ubuntu, `openssl-devel` on Fedora, or `brew install openssl@3` on macOS)

### Commands

```bash
# Build the pckt binary
make

# Run the automated unit and CLI integration test suite
make test

# Build and run tests with AddressSanitizer and UndefinedBehaviorSanitizer
make debug

# Strip symbols from the release binary
make strip

# Install to /usr/local/bin (override with PREFIX=/custom/path)
sudo make install

# Remove build artifacts
make clean
```
