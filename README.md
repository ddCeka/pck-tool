# pckt

A fast, lightweight command-line tool written in C for listing, unpacking, packing, and executable-bundling Godot `.pck` archives (versions v1–v4).

## Features

- **Format Support:** Reads and writes Godot PCK format versions `v1`, `v2`, `v3`, and `v4`.
- **Executable Unpacking & Embedding:** Extracts embedded `.pck` payloads directly from exported binaries (`.exe`, Linux, macOS) and re-bundles updated archives with `--embed`.
- **Encryption Support:** Decrypts AES-256-CFB encrypted directories and files via `--key` or `--key-file`.
- **Low Memory Footprint:** Uses read-only memory mapping (`mmap`) for inspection/extraction and chunked disk streaming for packing large archives.
- **Hardened Parser:** Validates paths against Zip Slip traversal, enforces strict alignment/endian-safe binary parsing, and skips `DEL` removal entries safely.

## Usage

```bash
pckt <unpack|pack|list> <in> [out] [options]
```

### Options

| Option | Description |
| :--- | :--- |
| `--key <64-hex>` | 64-character hexadecimal AES-256 decryption key |
| `--key-file <path>` | Path to a file containing the 64-character hex key |
| `--v1` \| `--v2` \| `--v3` \| `--v4` | Target PCK format version when packing (default: `v3`) |
| `--embed <exe>` | Bundle or replace the PCK inside a Godot executable when packing |

### Examples

- **List archive contents** sorted by file size:
  ```bash
  pckt list ./Game.pck
  ```
- **Extract files** from `Game.pck` into the `game_files` directory:
  ```bash
  pckt unpack ./Game.pck ./game_files
  ```
- **Extract an encrypted archive** using a key file:
  ```bash
  pckt unpack ./Game.pck ./game_files --key-file ./godot.gdkey
  ```
- **Pack a directory** into a Godot 4 (`v3`) `.pck` archive:
  ```bash
  pckt pack ./game_files ./Game.pck --v3
  ```
- **Bundle or re-pack a `.pck` directly into an executable**:
  ```bash
  pckt pack ./game_files ./Game_modded.exe --embed ./Game.exe
  ```

## Building & Testing

### Prerequisites

- A C11-compatible compiler (`gcc` or `clang`) and `make`
- OpenSSL development headers and `libcrypto` (`libssl-dev` on Debian/Ubuntu, or `brew install openssl@3` on macOS)

### Build Commands

- **Build the `pckt` binary:**
  ```bash
  make
  ```
- **Run the automated test suite (`test/test_pckt.c`):**
  ```bash
  make test
  ```
- **Run tests with AddressSanitizer and UndefinedBehaviorSanitizer:**
  ```bash
  make debug
  ```
- **Install system-wide (default `PREFIX=/usr/local`):**
  ```bash
  sudo make install
  ```
- **Clean build artifacts:**
  ```bash
  make clean
  ```
