# secrets

A command-line tool for generating secrets, updating configuration files, and encrypting/decrypting PASETO tokens.

## Installation

Build the tool from source:

```bash
go build -o secrets ./cmd/secrets
```

## Usage

```
secrets v1.0.0 - Generate secrets, update configs, or encrypt payloads

USAGE:
  secrets -f <file> -k <key> [options]
  secrets -l <length>             # print-only mode
  secrets --encrypt --secret <key> [--payload '<json|string>']
  secrets --encrypt --generate [--payload '<json|string>']
  secrets --decrypt --secret <key> --token <token-string>

EXAMPLES:
  secrets -f .env -k API_KEY
  secrets -l 48 --no-copy
  secrets --encrypt --secret $(cat key.txt) --payload '{"user_id":123}'

OPTIONS:
  -type string
        Configuration file type (env, json, yaml, yml, bcl)
  -t string
        Configuration file type (env, json, yaml, yml, bcl) (shorthand)
  -file string
        Path to configuration file
  -f string
        Path to configuration file (shorthand)
  -key string
        Key name to set/update
  -k string
        Key name to set/update (shorthand)
  -length int
        Length of the generated secret (default 32)
  -l int
        Length of the generated secret (shorthand) (default 32)
  -ttl string
        Token TTL (e.g. 60, 10s, m:5, 100 (s), 0 for infinite) (default "1h0m0s")
  -T string
        Token TTL (e.g. 60, 10s, m:5, 100 (s), 0 for infinite) (shorthand) (default "1h0m0s")
  -force
        Force overwrite without confirmation
  -backup
        Create backup of original file (default true)
  -b
        Create backup of original file (shorthand) (default true)
  -no-backup
        Disable backup creation
  -copy
        Copy generated secret to clipboard when printing (default true)
  -c
        Copy generated secret to clipboard when printing (shorthand) (default true)
  -no-copy
        Disable clipboard copy
  -encrypt
        Generate encrypted token instead of raw secret
  -E
        Generate encrypted token instead of raw secret (shorthand)
  -decrypt
        Decrypt an encrypted token
  -D
        Decrypt an encrypted token (shorthand)
  -generate
        Auto-generate a secret key when encrypting a payload
  -g
        Auto-generate a secret key when encrypting a payload (shorthand)
  -secret string
        Secret key material (32-byte raw, base64, or hex)
  -s string
        Secret key material (shorthand)
  -token string
        Encrypted token string for decryption
  -payload string
        Payload string or JSON to embed inside the token
  -p string
        Payload string or JSON to embed inside the token (shorthand)
  -verbose
        Enable verbose output (default true)
  -v
        Enable verbose output (shorthand) (default true)
  -version
        Show version information
```

## Flags

### Configuration File Options

- `-type`, `-t`: Specify the configuration file type. Supported types: `env`, `json`, `yaml`, `yml`, `bcl`. If not provided, auto-detection is attempted based on file extension.

- `-file`, `-f`: Path to the configuration file to update with the generated secret.

- `-key`, `-k`: The key name to set or update in the configuration file.

- `-length`, `-l`: Length of the generated secret in characters (default: 32, max: 1024).

- `-force`: Force overwrite without confirmation (useful for automation).

- `-backup`, `-b`: Create a backup of the original file before updating (default: true).

- `-no-backup`: Disable backup creation.

### Output Options

- `-copy`, `-c`: Copy the generated secret or token to the clipboard (default: true).

- `-no-copy`: Disable clipboard copying.

- `-verbose`, `-v`: Enable verbose output (default: true).

### Token Encryption/Decryption

- `-encrypt`, `-E`: Generate an encrypted PASETO token instead of a raw secret.

- `-decrypt`, `-D`: Decrypt an encrypted PASETO token.

- `-generate`, `-g`: Auto-generate a secret key when encrypting a payload (cannot be used with `-secret`).

- `-secret`, `-s`: Provide the secret key material (32-byte raw, base64, or hex encoded).

- `-token`: The encrypted token string to decrypt (required for `-decrypt`).

- `-payload`, `-p`: Payload string or JSON to embed inside the token (for encryption).

- `-ttl`, `-T`: Token Time-To-Live. Accepts various formats:
  - Plain seconds: `60` (60 seconds)
  - Go duration strings: `10s`, `5m`, `2h`, `1d`
  - Prefixed units: `m:5` (5 minutes), `h:2` (2 hours)
  - Parenthetical: `100 (s)` (100 seconds)
  - Infinite: `0`, `-1`, `inf`, `infinite`, `forever`, etc.

### Other

- `-version`: Display the version information.

## Examples

### Generate a Secret and Update a .env File

```bash
secrets -f .env -k API_KEY
```

Generates a 32-character secret and sets `API_KEY=<secret>` in `.env`.

### Generate a Secret of Specific Length Without File Update

```bash
secrets -l 64 --no-copy
```

Generates a 64-character secret and prints it without copying to clipboard.

### Encrypt a Payload with Auto-Generated Key

```bash
secrets --encrypt --generate --payload '{"user_id": 123, "role": "admin"}'
```

Generates a secret key, encrypts the JSON payload into a PASETO token, and prints the token.

### Encrypt a Payload with Custom TTL

```bash
secrets --encrypt --secret $(cat mykey.txt) --payload "Hello World" --ttl 30m
```

Uses the secret key from `mykey.txt`, encrypts "Hello World" with a 30-minute TTL.

### Encrypt with Infinite TTL

```bash
secrets --encrypt --generate --payload '{"data": "permanent"}' --ttl 0
```

Creates a token that never expires.

### Decrypt a Token

```bash
secrets --decrypt --secret $(cat mykey.txt) --token <encrypted_token>
```

Decrypts the token and displays its details, including expiration status.

### Various TTL Formats

```bash
# 10 seconds
secrets --encrypt --generate --ttl 10

# 5 minutes
secrets --encrypt --generate --ttl 5m

# 2 hours
secrets --encrypt --generate --ttl 2h

# 1 day
secrets --encrypt --generate --ttl 1d

# Prefixed: 5 minutes
secrets --encrypt --generate --ttl m:5

# Parenthetical: 100 seconds
secrets --encrypt --generate --ttl "100 (s)"

# Infinite
secrets --encrypt --generate --ttl inf
```

## Notes

- Secrets are generated using cryptographically secure random bytes.
- PASETO tokens use XChaCha20-Poly1305 encryption.
- Infinite TTL tokens use a very large expiration time (approximately 250 years).
- Clipboard functionality requires the `clipboard` package and may not work in all environments.
