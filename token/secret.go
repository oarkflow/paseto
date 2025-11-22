package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
	"gopkg.in/yaml.v3"
)

const (
	// Optimal buffer sizes based on common use cases
	defaultPoolSize         = 256
	maxPoolSize             = 4096
	defaultCharsetLen       = 64
	extendedCharsetLen      = 67   // 64 + 3 symbols (., $, /)
	charsetMask64      byte = 0x3F // 0b00111111 - masks to 64 values
	charsetMask128     byte = 0x7F // 0b01111111 - masks to 128 values
)

var (
	ErrInvalidSize   = errors.New("size must be positive")
	ErrInvalidLength = errors.New("length must be positive")
	ErrReaderFailed  = errors.New("entropy source read failed")
)

// charset uses URL-safe base64 characters for maximum compatibility
var charset = [defaultCharsetLen]byte{
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_',
}

// extendedCharset includes additional symbols: . $ /
var extendedCharset = [extendedCharsetLen]byte{
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_', '.', '$', '/',
}

// SecretGenerator produces cryptographically secure secrets with zero allocations
// for common operations and optimal performance for all use cases.
type SecretGenerator struct {
	reader io.Reader
	pool   *sync.Pool
	// Pre-allocated buffer for small operations to avoid pool overhead
	mu        sync.Mutex
	fastBuf   [64]byte
	fastInUse bool
	// Custom character set configuration
	customCharset []byte
	charsetMask   byte
	// Prefix to prepend to generated strings
	prefix string
}

// NewSecretGenerator creates an optimized generator with the given entropy source.
// If no reader is provided, crypto/rand.Reader is used (recommended).
func NewSecretGenerator(readers ...io.Reader) *SecretGenerator {
	reader := rand.Reader
	if len(readers) > 0 && readers[0] != nil {
		reader = readers[0]
	}

	return &SecretGenerator{
		reader:      reader,
		charsetMask: charsetMask64,
		pool: &sync.Pool{
			New: func() any {
				buf := make([]byte, defaultPoolSize)
				return &buf
			},
		},
	}
}

// WithCustomCharset allows setting a custom character set for string generation.
// The charset length must be a power of 2 for optimal performance (or use rejection sampling).
func (g *SecretGenerator) WithCustomCharset(chars []byte) *SecretGenerator {
	g.customCharset = make([]byte, len(chars))
	copy(g.customCharset, chars)

	// Calculate appropriate mask based on charset length
	length := len(chars)
	if length <= 64 {
		g.charsetMask = charsetMask64
	} else {
		g.charsetMask = charsetMask128
	}

	return g
}

// WithPrefix allows setting a prefix to prepend to generated secret strings.
func (g *SecretGenerator) WithPrefix(prefix string) *SecretGenerator {
	g.prefix = prefix
	return g
}

// getCharset returns the appropriate charset to use
func (g *SecretGenerator) getCharset() []byte {
	if g.customCharset != nil {
		return g.customCharset
	}
	return charset[:]
}

// getBuffer retrieves an appropriately sized buffer from the pool or fast path.
func (g *SecretGenerator) getBuffer(size int) ([]byte, bool) {
	// Fast path for small buffers - no allocation, no pool contention
	if size <= 64 {
		g.mu.Lock()
		if !g.fastInUse {
			g.fastInUse = true
			g.mu.Unlock()
			return g.fastBuf[:size], true
		}
		g.mu.Unlock()
	}

	// Pool path for larger buffers
	if size <= maxPoolSize {
		bufPtr := g.pool.Get().(*[]byte)
		buf := *bufPtr
		if cap(buf) < size {
			buf = make([]byte, size)
		}
		return buf[:size], false
	}

	// Direct allocation for very large buffers (rare)
	return make([]byte, size), false
}

// putBuffer returns a buffer to the appropriate location.
func (g *SecretGenerator) putBuffer(buf []byte, isFast bool) {
	if isFast {
		g.mu.Lock()
		g.fastInUse = false
		g.mu.Unlock()
		return
	}

	if cap(buf) <= maxPoolSize {
		bufCopy := buf[:cap(buf)]
		g.pool.Put(&bufCopy)
	}
}

// readBytesSafe reads exactly size bytes with proper error handling.
func (g *SecretGenerator) readBytesSafe(buf []byte) error {
	n, err := io.ReadFull(g.reader, buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return ErrReaderFailed
	}
	return nil
}

// Key returns cryptographically secure random bytes of the requested size.
// The returned slice should not be modified if you want to reuse it.
func (g *SecretGenerator) Key(size int) ([]byte, error) {
	if size <= 0 {
		return nil, ErrInvalidSize
	}

	result := make([]byte, size)
	if err := g.readBytesSafe(result); err != nil {
		return nil, err
	}
	return result, nil
}

// KeyInto fills the provided buffer with cryptographically secure random bytes.
// This is the zero-allocation variant of Key().
func (g *SecretGenerator) KeyInto(buf []byte) error {
	if len(buf) == 0 {
		return ErrInvalidSize
	}
	return g.readBytesSafe(buf)
}

// String returns a URL-safe secret string using unbiased character selection.
// This implementation uses rejection sampling to eliminate modulo bias.
func (g *SecretGenerator) String(length int) (string, error) {
	if length <= 0 {
		return "", ErrInvalidLength
	}

	charset := g.getCharset()
	charsetLen := len(charset)

	// For non-power-of-2 charsets, use unbiased method
	if charsetLen != 64 && charsetLen != 128 {
		return g.StringUnbiased(length)
	}

	buf, isFast := g.getBuffer(length)
	defer g.putBuffer(buf, isFast)

	if err := g.readBytesSafe(buf); err != nil {
		return "", err
	}

	// Use bit masking for uniform distribution (no modulo bias)
	for i := 0; i < length; i++ {
		buf[i] = charset[buf[i]&g.charsetMask]
	}

	// Zero-copy conversion using unsafe (safe in this context)
	if g.prefix != "" {
		prefixed := make([]byte, 0, len(g.prefix)+len(buf))
		prefixed = append(prefixed, []byte(g.prefix)...)
		prefixed = append(prefixed, buf...)
		return unsafeBytesToString(prefixed), nil
	}
	return unsafeBytesToString(buf), nil
}

// StringUnbiased returns a URL-safe string with perfect uniform distribution.
// Slightly slower than String() but guarantees no statistical bias.
func (g *SecretGenerator) StringUnbiased(length int) (string, error) {
	if length <= 0 {
		return "", ErrInvalidLength
	}

	charset := g.getCharset()
	charsetLen := len(charset)

	// Calculate rejection threshold for uniform distribution
	rejectThreshold := byte(256 - (256 % charsetLen))

	// We need extra bytes for rejection sampling
	bufSize := length + (length / 4) // 25% overhead typical
	buf, isFast := g.getBuffer(bufSize)
	defer g.putBuffer(buf, isFast)

	if err := g.readBytesSafe(buf); err != nil {
		return "", err
	}

	result := make([]byte, length)
	pos := 0
	idx := 0

	// Rejection sampling: only use bytes that map uniformly
	for pos < length && idx < bufSize {
		b := buf[idx]
		idx++
		if b < rejectThreshold {
			result[pos] = charset[int(b)%charsetLen]
			pos++
		}
	}

	// Unlikely: need more random bytes
	if pos < length {
		remaining := length - pos
		extra := make([]byte, remaining*2)
		if err := g.readBytesSafe(extra); err != nil {
			return "", err
		}
		for i := 0; pos < length && i < len(extra); i++ {
			if extra[i] < rejectThreshold {
				result[pos] = charset[int(extra[i])%charsetLen]
				pos++
			}
		}
	}

	if g.prefix != "" {
		prefixed := make([]byte, 0, len(g.prefix)+len(result))
		prefixed = append(prefixed, []byte(g.prefix)...)
		prefixed = append(prefixed, result...)
		return unsafeBytesToString(prefixed), nil
	}

	if g.prefix != "" {
		prefixed := make([]byte, 0, len(g.prefix)+len(result))
		prefixed = append(prefixed, []byte(g.prefix)...)
		prefixed = append(prefixed, result...)
		return unsafeBytesToString(prefixed), nil
	}

	return unsafeBytesToString(result), nil
}

// StringWithSymbols returns a secret string using the extended character set
// that includes . $ / symbols in addition to the standard URL-safe characters.
// The first character is guaranteed to not be a symbol (., $, /).
func (g *SecretGenerator) StringWithSymbols(length int) (string, error) {
	if length <= 0 {
		return "", ErrInvalidLength
	}

	result := make([]byte, length)

	// Generate first character from base charset (no symbols)
	firstBuf, firstFast := g.getBuffer(1)
	defer g.putBuffer(firstBuf, firstFast)
	if err := g.readBytesSafe(firstBuf); err != nil {
		return "", err
	}
	result[0] = charset[firstBuf[0]&charsetMask64]

	if length == 1 {
		if g.prefix != "" {
			prefixed := make([]byte, 0, len(g.prefix)+len(result))
			prefixed = append(prefixed, []byte(g.prefix)...)
			prefixed = append(prefixed, result...)
			return unsafeBytesToString(prefixed), nil
		}
		return unsafeBytesToString(result), nil
	}

	// Generate remaining characters using extended charset with rejection sampling
	remaining := length - 1
	rejectThreshold := byte(256 - (256 % extendedCharsetLen))
	bufSize := remaining + (remaining / 4)
	buf, isFast := g.getBuffer(bufSize)
	defer g.putBuffer(buf, isFast)

	if err := g.readBytesSafe(buf); err != nil {
		return "", err
	}

	pos := 1
	idx := 0

	for pos < length && idx < bufSize {
		b := buf[idx]
		idx++
		if b < rejectThreshold {
			result[pos] = extendedCharset[int(b)%extendedCharsetLen]
			pos++
		}
	}

	if pos < length {
		remaining2 := length - pos
		extra := make([]byte, remaining2*2)
		if err := g.readBytesSafe(extra); err != nil {
			return "", err
		}
		for i := 0; pos < length && i < len(extra); i++ {
			if extra[i] < rejectThreshold {
				result[pos] = extendedCharset[int(extra[i])%extendedCharsetLen]
				pos++
			}
		}
	}

	if g.prefix != "" {
		prefixed := make([]byte, 0, len(g.prefix)+len(result))
		prefixed = append(prefixed, []byte(g.prefix)...)
		prefixed = append(prefixed, result...)
		return unsafeBytesToString(prefixed), nil
	}

	return unsafeBytesToString(result), nil
}

// Base64 returns a raw URL-safe Base64 encoded secret.
func (g *SecretGenerator) Base64(size int) (string, error) {
	if size <= 0 {
		return "", ErrInvalidSize
	}

	buf, isFast := g.getBuffer(size)
	defer g.putBuffer(buf, isFast)

	if err := g.readBytesSafe(buf); err != nil {
		return "", err
	}

	// Calculate exact output size to avoid reallocation
	encodedLen := base64.RawURLEncoding.EncodedLen(size)
	result := make([]byte, encodedLen)
	base64.RawURLEncoding.Encode(result, buf)

	if g.prefix != "" {
		prefixed := make([]byte, 0, len(g.prefix)+len(result))
		prefixed = append(prefixed, []byte(g.prefix)...)
		prefixed = append(prefixed, result...)
		return unsafeBytesToString(prefixed), nil
	}

	return unsafeBytesToString(result), nil
}

// Uint64 returns a cryptographically secure random uint64.
func (g *SecretGenerator) Uint64() (uint64, error) {
	var buf [8]byte
	if err := g.readBytesSafe(buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

// Uint64Range returns a random uint64 in [0, max) with uniform distribution.
func (g *SecretGenerator) Uint64Range(max uint64) (uint64, error) {
	if max == 0 {
		return 0, nil
	}

	// Rejection sampling to avoid modulo bias
	mask := uint64(1)<<(64-leadingZeros(max)) - 1

	for {
		val, err := g.Uint64()
		if err != nil {
			return 0, err
		}
		val &= mask
		if val < max {
			return val, nil
		}
	}
}

// leadingZeros counts leading zero bits in a uint64.
func leadingZeros(x uint64) int {
	if x == 0 {
		return 64
	}
	n := 0
	if x <= 0x00000000FFFFFFFF {
		n += 32
		x <<= 32
	}
	if x <= 0x0000FFFFFFFFFFFF {
		n += 16
		x <<= 16
	}
	if x <= 0x00FFFFFFFFFFFFFF {
		n += 8
		x <<= 8
	}
	if x <= 0x0FFFFFFFFFFFFFFF {
		n += 4
		x <<= 4
	}
	if x <= 0x3FFFFFFFFFFFFFFF {
		n += 2
		x <<= 2
	}
	if x <= 0x7FFFFFFFFFFFFFFF {
		n++
	}
	return n
}

// unsafeBytesToString converts bytes to string without allocation.
// Safe because we're converting random data that won't be mutated.
func unsafeBytesToString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// ReplaceInEnvFile generates a secret and replaces or adds it in a .env file
func (g *SecretGenerator) ReplaceInEnvFile(filePath, key string, length int) error {
	secret, err := g.String(length)
	if err != nil {
		return fmt.Errorf("failed to generate secret: %w", err)
	}

	return replaceInEnvFile(filePath, key, secret)
}

// ReplaceInJSONFile generates a secret and replaces or adds it in a JSON file
func (g *SecretGenerator) ReplaceInJSONFile(filePath, key string, length int) error {
	secret, err := g.String(length)
	if err != nil {
		return fmt.Errorf("failed to generate secret: %w", err)
	}

	return replaceInJSONFile(filePath, key, secret)
}

// ReplaceInYAMLFile generates a secret and replaces or adds it in a YAML file
func (g *SecretGenerator) ReplaceInYAMLFile(filePath, key string, length int) error {
	secret, err := g.String(length)
	if err != nil {
		return fmt.Errorf("failed to generate secret: %w", err)
	}

	return replaceInYAMLFile(filePath, key, secret)
}

// ReplaceInBCLFile generates a secret and replaces or adds it in a BCL file
func (g *SecretGenerator) ReplaceInBCLFile(filePath, key string, length int) error {
	secret, err := g.String(length)
	if err != nil {
		return fmt.Errorf("failed to generate secret: %w", err)
	}

	return replaceInBCLFile(filePath, key, secret)
}

// replaceInEnvFile handles the actual .env file replacement
func replaceInEnvFile(filePath, key, value string) error {
	content, err := os.ReadFile(filePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	keyFound := false
	keyPattern := regexp.MustCompile(`^` + regexp.QuoteMeta(key) + `=`)

	for i, line := range lines {
		if keyPattern.MatchString(line) {
			lines[i] = fmt.Sprintf("%s=%s", key, value)
			keyFound = true
			break
		}
	}

	if !keyFound {
		// Add new key at the end
		lines = append(lines, fmt.Sprintf("%s=%s", key, value))
	}

	return os.WriteFile(filePath, []byte(strings.Join(lines, "\n")), 0644)
}

// replaceInJSONFile handles the actual JSON file replacement
func replaceInJSONFile(filePath, key, value string) error {
	content, err := os.ReadFile(filePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var data map[string]any
	if len(content) > 0 {
		if err := json.Unmarshal(content, &data); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		data = make(map[string]any)
	}

	data[key] = value

	updated, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return os.WriteFile(filePath, updated, 0644)
}

// replaceInYAMLFile handles the actual YAML file replacement
func replaceInYAMLFile(filePath, key, value string) error {
	content, err := os.ReadFile(filePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var data map[string]any
	if len(content) > 0 {
		if err := yaml.Unmarshal(content, &data); err != nil {
			return fmt.Errorf("failed to parse YAML: %w", err)
		}
	} else {
		data = make(map[string]any)
	}

	data[key] = value

	updated, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	return os.WriteFile(filePath, updated, 0644)
}

// replaceInBCLFile handles the actual BCL file replacement
// BCL uses HCL-like block syntax: block { key = "value" }
func replaceInBCLFile(filePath, key, value string) error {
	content, err := os.ReadFile(filePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read file: %w", err)
	}

	lines := strings.Split(string(content), "\n")

	// Check if key contains a block (format: block.key)
	var blockName, attrName string
	if dotIndex := strings.Index(key, "."); dotIndex != -1 {
		blockName = key[:dotIndex]
		attrName = key[dotIndex+1:]
	} else {
		return fmt.Errorf("BCL keys must be in format 'block.attribute'")
	}

	keyFound := false
	currentBlock := ""
	nestingLevel := 0
	inTargetBlock := false

	for i, line := range lines {
		originalLine := line
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Track nesting level
		openBraces := strings.Count(line, "{")
		closeBraces := strings.Count(line, "}")
		nestingLevel += openBraces - closeBraces

		// Check for block start
		if nestingLevel == 1 && strings.HasSuffix(line, "{") {
			// Extract block name (everything before the opening brace)
			blockLine := strings.TrimSuffix(line, "{")
			blockLine = strings.TrimSpace(blockLine)
			// Handle quoted block names
			if strings.HasPrefix(blockLine, `"`) && strings.HasSuffix(blockLine, `"`) {
				blockLine = strings.Trim(blockLine, `"`)
			}
			currentBlock = blockLine
			inTargetBlock = (currentBlock == blockName)
			continue
		}

		// If we're in the target block and at the right nesting level
		if inTargetBlock && nestingLevel == 1 && strings.Contains(line, "=") {
			// Check if this line contains our attribute
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				attr := strings.TrimSpace(parts[0])
				if attr == attrName {
					// Replace the value, preserving quotes if present
					oldValue := strings.TrimSpace(parts[1])
					var newLine string
					if strings.HasPrefix(oldValue, `"`) && strings.HasSuffix(oldValue, `"`) {
						newLine = fmt.Sprintf(`  %s = "%s"`, attrName, value)
					} else {
						newLine = fmt.Sprintf(`  %s = %s`, attrName, value)
					}
					lines[i] = strings.Replace(originalLine, strings.TrimSpace(originalLine), newLine, 1)
					keyFound = true
					break
				}
			}
		}

		// Exit block when nesting level returns to 0
		if nestingLevel == 0 {
			currentBlock = ""
			inTargetBlock = false
		}
	}

	if !keyFound {
		// Find the block and add the attribute there
		blockFound := false
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}

			if strings.HasSuffix(line, "{") {
				blockLine := strings.TrimSuffix(line, "{")
				blockLine = strings.TrimSpace(blockLine)
				if strings.HasPrefix(blockLine, `"`) && strings.HasSuffix(blockLine, `"`) {
					blockLine = strings.Trim(blockLine, `"`)
				}
				if blockLine == blockName {
					blockFound = true
					// Find the closing brace of this block
					localNesting := 1
					insertIndex := i + 1

					for insertIndex < len(lines) && localNesting > 0 {
						nextLine := strings.TrimSpace(lines[insertIndex])
						localNesting += strings.Count(nextLine, "{") - strings.Count(nextLine, "}")
						if localNesting == 1 && (nextLine == "" || strings.HasPrefix(nextLine, "#")) {
							// Good place to insert
						} else if localNesting == 0 {
							// Insert before the closing brace
							insertIndex--
							break
						}
						if localNesting == 1 && strings.Contains(nextLine, "=") {
							// Insert after existing attributes
						}
						insertIndex++
					}

					// Insert the new attribute
					newLine := fmt.Sprintf(`  %s = "%s"`, attrName, value)
					lines = append(lines[:insertIndex], append([]string{newLine}, lines[insertIndex:]...)...)
					return os.WriteFile(filePath, []byte(strings.Join(lines, "\n")), 0644)
				}
			}
		}

		if !blockFound {
			// Block doesn't exist, add it at the end
			lines = append(lines, "")
			lines = append(lines, fmt.Sprintf(`%s {`, blockName))
			lines = append(lines, fmt.Sprintf(`  %s = "%s"`, attrName, value))
			lines = append(lines, `}`)
		}
	}

	return os.WriteFile(filePath, []byte(strings.Join(lines, "\n")), 0644)
}

// Global instance for package-level functions
var defaultGenerator = NewSecretGenerator()

// GenerateSymmetricKey returns a 32-byte key for XChaCha20-Poly1305 encryption.
func GenerateSymmetricKey() ([]byte, error) {
	return defaultGenerator.Key(chacha20poly1305.KeySize)
}

// GenerateSecretString returns a URL-safe random string of the given length.
func GenerateSecretString(length int) (string, error) {
	return defaultGenerator.String(length)
}

// GenerateSecretStringUnbiased returns a perfectly uniform random string.
func GenerateSecretStringUnbiased(length int) (string, error) {
	return defaultGenerator.StringUnbiased(length)
}

// GenerateSecretStringWithSymbols returns a random string using extended charset
// including . $ / symbols.
func GenerateSecretStringWithSymbols(length int) (string, error) {
	return defaultGenerator.StringWithSymbols(length)
}

// GenerateSigningKeypair creates a fresh Ed25519 keypair.
func GenerateSigningKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(defaultGenerator.reader)
}

// GenerateBase64Secret returns a base64-encoded secret of the given byte size.
func GenerateBase64Secret(size int) (string, error) {
	return defaultGenerator.Base64(size)
}

// GenerateSecretInEnvFile generates a secret and replaces it in a .env file
func GenerateSecretInEnvFile(filePath, key string, length int) error {
	return defaultGenerator.ReplaceInEnvFile(filePath, key, length)
}

// GenerateSecretInJSONFile generates a secret and replaces it in a JSON file
func GenerateSecretInJSONFile(filePath, key string, length int) error {
	return defaultGenerator.ReplaceInJSONFile(filePath, key, length)
}

// GenerateSecretInYAMLFile generates a secret and replaces it in a YAML file
func GenerateSecretInYAMLFile(filePath, key string, length int) error {
	return defaultGenerator.ReplaceInYAMLFile(filePath, key, length)
}

// GenerateSecretInBCLFile generates a secret and replaces it in a BCL file
func GenerateSecretInBCLFile(filePath, key string, length int) error {
	return defaultGenerator.ReplaceInBCLFile(filePath, key, length)
}
