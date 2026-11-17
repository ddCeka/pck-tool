# pckt

A fast, lightweight command-line tool written in C for inspecting, unpacking, and building Godot `.pck` archives and self-contained executables (Godot PCK formats **v1–v4**).

## Features
- **Zero-Copy & Streaming I/O:** Uses `mmap` for `list` and `unpack` and 64 KB chunked disk streaming for `pack`, keeping memory usage minimal even on multi-gigabyte archives.
- **Standalone & Embedded Support:** Reads and writes standalone `.pck` files as well as self-contained Windows/Linux/macOS executables (`--embed`).
- **Metadata Cloning:** Automatically matches the original game's PCK format version and Godot engine version via `--copy-meta` or `--engine`.
- **Deterministic Builds:** Sorts input paths lexicographically so packing the same directory produces byte-for-byte identical archives across filesystems.
- **AES-256-CFB Decryption:** Supports decrypting V2–V4 encrypted directories and files via `--key` or `--key-file`.
- **Hardened Parser:** Protects against Zip Slip path traversal, unaligned memory access, and integer overflows.

## Usage

```text
pckt <unpack|pack|list> <in> [out] [options]
```

### Options
| Option | Mode | Description |
| :--- | :--- | :--- |
| `--v1`, `--v2`, `--v3`, `--v4` | `pack` | Target PCK format version (default: `v3`). |
| `--engine <M.m.p>` | `pack` | Set the Godot engine version in the header (e.g. `4.3.0`). |
| `--copy-meta <pck\|exe>` | `pack` | Copy the PCK format and Godot engine version from an existing archive or executable. |
| `--embed <exe>` | `pack` | Bundle the packed archive into a Godot executable (strips any previously embedded PCK first). |
| `--key <64-hex>` | `unpack`, `list` | 64-character hexadecimal AES-256 decryption key. |
| `--key-file <path>` | `unpack`, `list` | Read the 64-character hexadecimal AES-256 key from a file. |

### Examples

- **List archive contents sorted by size:**
  ```bash
  pckt list ./Game.pck
  ```

- **Unpack a standalone `.pck` or self-contained executable:**
  ```bash
  pckt unpack ./Game.pck ./game_files
  pckt unpack ./Game.exe ./game_files
  ```

- **Unpack an encrypted archive:**
  ```bash
  pckt unpack ./Game.pck ./game_files --key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  pckt unpack ./Game.pck ./game_files --key-file ./godot.gdkey
  ```

- **Repack modified assets matching the original game's metadata:**
  ```bash
  pckt pack ./game_files ./Game_patched.pck --copy-meta ./Game.pck
  ```

- **Re-bundle modified assets directly into a Godot executable:**
  ```bash
  pckt pack ./game_files ./Game_patched.exe --copy-meta ./Game.exe --embed ./Game.exe
  ```

## Building & Testing

### Prerequisites
- C11-compatible compiler (`gcc` or `clang`)
- `make`
- OpenSSL development headers (`libssl-dev` on Debian/Ubuntu, `openssl@3` via Homebrew on macOS)

### Commands
- **Build the binary:**
  ```bash
  make
  ```
- **Run the test suite:**
  ```bash
  make test
  ```
- **Run tests with AddressSanitizer & UndefinedBehaviorSanitizer:**
  ```bash
  make debug
  ```
- **Strip debug symbols or install system-wide:**
  ```bash
  make strip
  sudo make install
  ```
