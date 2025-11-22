package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/oarkflow/paseto/token"
)

const (
	version             = "1.0.0"
	defaultEncryptTTL   = time.Hour
	symmetricKeyLength  = 32
	infiniteTTLDuration = 250 * 365 * 24 * time.Hour
)

var ttlUnitMultipliers = map[string]time.Duration{
	"":        time.Second,
	"s":       time.Second,
	"sec":     time.Second,
	"secs":    time.Second,
	"second":  time.Second,
	"seconds": time.Second,
	"m":       time.Minute,
	"min":     time.Minute,
	"mins":    time.Minute,
	"minute":  time.Minute,
	"minutes": time.Minute,
	"h":       time.Hour,
	"hr":      time.Hour,
	"hrs":     time.Hour,
	"hour":    time.Hour,
	"hours":   time.Hour,
	"d":       24 * time.Hour,
	"day":     24 * time.Hour,
	"days":    24 * time.Hour,
}

type Config struct {
	FileType        string
	FilePath        string
	Key             string
	Length          int
	TTLInput        string
	Force           bool
	Backup          bool
	Verbose         bool
	ShowVersion     bool
	CopyToClipboard bool
	EncryptToken    bool
	DecryptToken    bool
	SecretKeyInput  string
	SecretKeyBytes  []byte
	Payload         string
	GenerateSecret  bool
	GeneratedSecret string
	TokenInput      string
	EncryptTTL      time.Duration
	InfiniteTTL     bool
}

func main() {
	config := parseFlags()

	if config.ShowVersion {
		fmt.Printf("paseto-secret v%s\n", version)
		os.Exit(0)
	}

	if err := validateConfig(config); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	if config.DecryptToken {
		if _, err := processDecryption(config); err != nil {
			log.Fatalf("Token decryption failed: %v", err)
		}
		return
	}

	if config.EncryptToken {
		encrypted, err := generateEncryptedToken(config)
		if err != nil {
			log.Fatalf("Token encryption failed: %v", err)
		}
		if config.Verbose {
			copied := ""
			if config.CopyToClipboard {
				copied = " (copied to clipboard)"
			}
			fmt.Printf("✓ Encrypted token ready%s [len=%d]\n", copied, len(encrypted))
		}
		return
	}

	secret, err := runSecretGeneration(config)
	if err != nil {
		log.Fatalf("Secret generation failed: %v", err)
	}

	if config.FilePath == "" {
		if config.Verbose {
			copied := ""
			if config.CopyToClipboard {
				copied = " (copied to clipboard)"
			}
			fmt.Printf("✓ Secret ready%s [len=%d]\n", copied, len(secret))
		}
		return
	}

	if config.Verbose {
		fmt.Printf("✓ Successfully generated and set secret for key '%s' in %s\n", config.Key, config.FilePath)
	}
}

func parseFlags() *Config {
	config := &Config{}
	defaultTTLString := defaultEncryptTTL.String()

	flag.StringVar(&config.FileType, "type", "", "Configuration file type (env, json, yaml, yml, bcl)")
	flag.StringVar(&config.FileType, "t", "", "Configuration file type (env, json, yaml, yml, bcl) (shorthand)")
	flag.StringVar(&config.FilePath, "file", "", "Path to configuration file")
	flag.StringVar(&config.FilePath, "f", "", "Path to configuration file (shorthand)")
	flag.StringVar(&config.Key, "key", "", "Key name to set/update")
	flag.StringVar(&config.Key, "k", "", "Key name to set/update (shorthand)")
	flag.IntVar(&config.Length, "length", 32, "Length of the generated secret")
	flag.IntVar(&config.Length, "l", 32, "Length of the generated secret (shorthand)")
	flag.StringVar(&config.TTLInput, "ttl", defaultTTLString, "Token TTL (e.g. 60, 10s, m:5, 100 (s), 0 for infinite)")
	flag.StringVar(&config.TTLInput, "T", defaultTTLString, "Token TTL (e.g. 60, 10s, m:5, 100 (s), 0 for infinite) (shorthand)")
	flag.BoolVar(&config.Force, "force", false, "Force overwrite without confirmation")
	flag.BoolVar(&config.Backup, "backup", true, "Create backup of original file")
	flag.BoolVar(&config.Backup, "b", true, "Create backup of original file (shorthand)")
	noBackup := flag.Bool("no-backup", false, "Disable backup creation")
	flag.BoolVar(&config.CopyToClipboard, "copy", true, "Copy generated secret to clipboard when printing")
	flag.BoolVar(&config.CopyToClipboard, "c", true, "Copy generated secret to clipboard when printing (shorthand)")
	noCopy := flag.Bool("no-copy", false, "Disable clipboard copy")
	flag.BoolVar(&config.EncryptToken, "encrypt", false, "Generate encrypted token instead of raw secret")
	flag.BoolVar(&config.EncryptToken, "E", false, "Generate encrypted token instead of raw secret (shorthand)")
	flag.BoolVar(&config.DecryptToken, "decrypt", false, "Decrypt an encrypted token")
	flag.BoolVar(&config.DecryptToken, "D", false, "Decrypt an encrypted token (shorthand)")
	flag.BoolVar(&config.GenerateSecret, "generate", false, "Auto-generate a secret key when encrypting a payload")
	flag.BoolVar(&config.GenerateSecret, "g", false, "Auto-generate a secret key when encrypting a payload (shorthand)")
	flag.StringVar(&config.SecretKeyInput, "secret", "", "Secret key material (32-byte raw, base64, or hex)")
	flag.StringVar(&config.SecretKeyInput, "s", "", "Secret key material (shorthand)")
	flag.StringVar(&config.TokenInput, "token", "", "Encrypted token string for decryption")
	flag.StringVar(&config.Payload, "payload", "", "Payload string or JSON to embed inside the token")
	flag.StringVar(&config.Payload, "p", "", "Payload string or JSON to embed inside the token (shorthand)")
	flag.BoolVar(&config.Verbose, "verbose", true, "Enable verbose output")
	flag.BoolVar(&config.Verbose, "v", true, "Enable verbose output (shorthand)")
	showVersion := flag.Bool("version", false, "Show version information")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "paseto-secret v%s - Generate secrets, update configs, or encrypt payloads\n\n", version)
		fmt.Fprintf(os.Stderr, "USAGE:\n")
		fmt.Fprintf(os.Stderr, "  paseto-secret -f <file> -k <key> [options]\n")
		fmt.Fprintf(os.Stderr, "  paseto-secret -l <length>             # print-only mode\n")
		fmt.Fprintf(os.Stderr, "  paseto-secret --encrypt --secret <key> [--payload '<json|string>']\n")
		fmt.Fprintf(os.Stderr, "  paseto-secret --encrypt --generate [--payload '<json|string>']\n")
		fmt.Fprintf(os.Stderr, "  paseto-secret --decrypt --secret <key> --token <token-string>\n\n")
		fmt.Fprintf(os.Stderr, "EXAMPLES:\n")
		fmt.Fprintf(os.Stderr, "  paseto-secret -f .env -k API_KEY\n")
		fmt.Fprintf(os.Stderr, "  paseto-secret -l 48 --no-copy\n")
		fmt.Fprintf(os.Stderr, "  paseto-secret --encrypt --secret $(cat key.txt) --payload '{\"user_id\":123}'\n\n")
		fmt.Fprintf(os.Stderr, "OPTIONS:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	config.ShowVersion = *showVersion

	// Handle helper flags
	if *noBackup {
		config.Backup = false
	}
	if *noCopy {
		config.CopyToClipboard = false
	}

	return config
}

func validateConfig(config *Config) error {
	if config.DecryptToken {
		if config.EncryptToken {
			return fmt.Errorf("--encrypt and --decrypt cannot be used together")
		}
		if config.GenerateSecret {
			return fmt.Errorf("--generate cannot be used with --decrypt")
		}
		if strings.TrimSpace(config.TokenInput) == "" {
			return fmt.Errorf("token string is required when --decrypt is set")
		}
		if strings.TrimSpace(config.SecretKeyInput) == "" {
			return fmt.Errorf("secret key is required when --decrypt is set")
		}
		keyBytes, err := decodeSecretKey(config.SecretKeyInput)
		if err != nil {
			return err
		}
		config.SecretKeyBytes = keyBytes
		return nil
	}

	if config.EncryptToken {
		if config.GenerateSecret {
			if strings.TrimSpace(config.SecretKeyInput) != "" {
				return fmt.Errorf("--secret cannot be used together with --generate")
			}
			secretStr, secretBytes, err := generateSecretKeyMaterial()
			if err != nil {
				return fmt.Errorf("failed to generate secret key: %w", err)
			}
			config.GeneratedSecret = secretStr
			config.SecretKeyBytes = secretBytes
		} else {
			if strings.TrimSpace(config.SecretKeyInput) == "" {
				return fmt.Errorf("secret key is required when --encrypt is set (or use --generate)")
			}
			keyBytes, err := decodeSecretKey(config.SecretKeyInput)
			if err != nil {
				return err
			}
			config.SecretKeyBytes = keyBytes
		}

		ttlDuration, infinite, err := parseTTLInput(config.TTLInput)
		if err != nil {
			return err
		}
		config.EncryptTTL = ttlDuration
		config.InfiniteTTL = infinite
		return nil
	}
	if config.GenerateSecret {
		return fmt.Errorf("--generate can only be used together with --encrypt")
	}

	if config.Length <= 0 {
		return fmt.Errorf("secret length must be positive")
	}

	if config.Length > 1024 {
		return fmt.Errorf("secret length cannot exceed 1024 characters")
	}

	// Print-only mode: no further validation required
	if config.FilePath == "" {
		return nil
	}

	if config.Key == "" {
		return fmt.Errorf("key name is required (-k flag) when --file is provided")
	}

	if config.FileType == "" {
		detected, err := detectFileType(config.FilePath)
		if err != nil {
			return err
		}
		config.FileType = detected
		if config.Verbose {
			fmt.Printf("Auto-detected file type '%s' for %s\n", detected, config.FilePath)
		}
	}

	config.FileType = strings.ToLower(config.FileType)
	validTypes := map[string]bool{
		"env":  true,
		"json": true,
		"yaml": true,
		"yml":  true,
		"bcl":  true,
	}
	if !validTypes[config.FileType] {
		return fmt.Errorf("unsupported file type '%s'. Supported types: env, json, yaml, yml, bcl", config.FileType)
	}

	if _, err := os.Stat(config.FilePath); os.IsNotExist(err) {
		if config.Verbose {
			fmt.Printf("Warning: File '%s' does not exist, it will be created\n", config.FilePath)
		}
	}

	return nil
}

func runSecretGeneration(config *Config) (string, error) {
	if config.FilePath == "" {
		secret, err := token.GenerateSecretString(config.Length)
		if err != nil {
			return "", fmt.Errorf("failed to generate secret: %w", err)
		}
		fmt.Printf("Generated secret (%d chars): %s\n", len(secret), secret)
		if config.CopyToClipboard {
			copySecretToClipboard(secret, config.Verbose)
		}
		return secret, nil
	}

	// Create backup if requested and file exists
	if config.Backup {
		if err := createBackup(config.FilePath); err != nil {
			if config.Verbose {
				fmt.Printf("Warning: Failed to create backup: %v\n", err)
			}
		} else if config.Verbose {
			fmt.Printf("✓ Created backup: %s.bak\n", config.FilePath)
		}
	}

	// Generate and set secret based on file type
	fileType := strings.ToLower(config.FileType)
	var err error

	switch fileType {
	case "env":
		err = token.GenerateSecretInEnvFile(config.FilePath, config.Key, config.Length)
	case "json":
		err = token.GenerateSecretInJSONFile(config.FilePath, config.Key, config.Length)
	case "yaml", "yml":
		err = token.GenerateSecretInYAMLFile(config.FilePath, config.Key, config.Length)
	case "bcl":
		err = token.GenerateSecretInBCLFile(config.FilePath, config.Key, config.Length)
	default:
		return "", fmt.Errorf("unsupported file type: %s", fileType)
	}

	if err != nil {
		return "", fmt.Errorf("failed to update %s file: %w", fileType, err)
	}

	return "", nil
}

func generateEncryptedToken(config *Config) (string, error) {
	claims, err := parsePayloadClaims(config.Payload)
	if err != nil {
		return "", err
	}
	ttl := defaultEncryptTTL
	if config.EncryptTTL > 0 {
		ttl = config.EncryptTTL
	}
	t := token.CreateToken(ttl, token.AlgEncrypt)
	if config.Verbose {
		switch {
		case config.InfiniteTTL:
			fmt.Println("Using infinite TTL for encrypted token")
		case ttl != defaultEncryptTTL:
			fmt.Printf("Using custom TTL: %s\n", ttl)
		}
	}
	if len(claims) > 0 {
		if err := t.RegisterClaims(claims); err != nil {
			return "", err
		}
	}
	if config.GenerateSecret && config.GeneratedSecret != "" {
		fmt.Printf("Generated secret key (%d bytes, base64): %s\n", symmetricKeyLength, config.GeneratedSecret)
	}
	encoded, err := token.EncryptToken(t, config.SecretKeyBytes)
	if err != nil {
		return "", err
	}
	fmt.Printf("Encrypted token (%d chars): %s\n", len(encoded), encoded)
	if config.CopyToClipboard {
		copySecretToClipboard(encoded, config.Verbose)
	}
	return encoded, nil
}

func parsePayloadClaims(payload string) (map[string]any, error) {
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" {
		return nil, nil
	}
	var val any
	if err := json.Unmarshal([]byte(trimmed), &val); err == nil {
		switch cast := val.(type) {
		case map[string]any:
			return cast, nil
		default:
			return map[string]any{"payload": cast}, nil
		}
	}
	return map[string]any{"payload": trimmed}, nil
}

func parseTTLInput(raw string) (time.Duration, bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultEncryptTTL, false, nil
	}
	lower := strings.ToLower(trimmed)
	if isInfiniteKeyword(lower) {
		return infiniteTTLDuration, true, nil
	}
	noSpaces := strings.ReplaceAll(lower, " ", "")
	if d, err := time.ParseDuration(noSpaces); err == nil {
		if d == 0 {
			return infiniteTTLDuration, true, nil
		}
		if d < 0 {
			return 0, false, fmt.Errorf("ttl must be positive, got %s", raw)
		}
		if d > infiniteTTLDuration {
			return 0, false, fmt.Errorf("ttl exceeds maximum supported duration of %s", infiniteTTLDuration)
		}
		return d, false, nil
	}
	if dur, inf, matched, err := parseDelimitedDuration(lower); matched {
		return dur, inf, err
	}
	if dur, inf, matched, err := parseParentheticalDuration(lower); matched {
		return dur, inf, err
	}
	if dur, inf, matched, err := parseUnitPrefixedDuration(lower); matched {
		return dur, inf, err
	}
	numericCandidate := strings.ReplaceAll(noSpaces, "_", "")
	if seconds, err := strconv.ParseFloat(numericCandidate, 64); err == nil {
		return durationFromSeconds(seconds)
	}
	return 0, false, fmt.Errorf("unable to parse ttl value %q", raw)
}

func parseDelimitedDuration(input string) (time.Duration, bool, bool, error) {
	for _, sep := range []string{":", "="} {
		if idx := strings.Index(input, sep); idx > 0 {
			unit := strings.TrimSpace(input[:idx])
			value := strings.TrimSpace(input[idx+len(sep):])
			if unit == "" || value == "" {
				continue
			}
			dur, inf, err := durationFromUnitValue(value, unit)
			return dur, inf, true, err
		}
	}
	return 0, false, false, nil
}

func parseParentheticalDuration(input string) (time.Duration, bool, bool, error) {
	open := strings.Index(input, "(")
	close := strings.LastIndex(input, ")")
	if open > 0 && close > open {
		value := strings.TrimSpace(input[:open])
		unit := strings.TrimSpace(input[open+1 : close])
		if value == "" || unit == "" {
			return 0, false, true, fmt.Errorf("invalid ttl format %q", input)
		}
		dur, inf, err := durationFromUnitValue(value, unit)
		return dur, inf, true, err
	}
	return 0, false, false, nil
}

func parseUnitPrefixedDuration(input string) (time.Duration, bool, bool, error) {
	if len(input) < 2 {
		return 0, false, false, nil
	}
	first := input[0]
	if first < 'a' || first > 'z' {
		return 0, false, false, nil
	}
	idx := 0
	for idx < len(input) {
		ch := input[idx]
		if (ch < 'a' || ch > 'z') && ch != '_' {
			break
		}
		idx++
	}
	if idx == 0 || idx == len(input) {
		return 0, false, false, nil
	}
	unit := strings.Trim(input[:idx], "_")
	value := strings.TrimSpace(input[idx:])
	if unit == "" || value == "" {
		return 0, false, false, nil
	}
	dur, inf, err := durationFromUnitValue(value, unit)
	return dur, inf, true, err
}

func durationFromUnitValue(valueStr, unitStr string) (time.Duration, bool, error) {
	normalizedUnit := normalizeTTLUnit(unitStr)
	multiplier, ok := ttlUnitMultipliers[normalizedUnit]
	if !ok {
		return 0, false, fmt.Errorf("unsupported ttl unit %q", unitStr)
	}
	cleanValue := strings.ReplaceAll(strings.TrimSpace(valueStr), "_", "")
	if cleanValue == "" {
		return 0, false, fmt.Errorf("missing ttl value for unit %q", unitStr)
	}
	val, err := strconv.ParseFloat(cleanValue, 64)
	if err != nil {
		return 0, false, fmt.Errorf("invalid ttl magnitude %q: %w", valueStr, err)
	}
	seconds := val * multiplier.Seconds()
	return durationFromSeconds(seconds)
}

func durationFromSeconds(seconds float64) (time.Duration, bool, error) {
	if seconds == 0 {
		return infiniteTTLDuration, true, nil
	}
	if seconds < 0 {
		if seconds == -1 {
			return infiniteTTLDuration, true, nil
		}
		return 0, false, fmt.Errorf("ttl must be positive, got %v seconds", seconds)
	}
	nanos := seconds * float64(time.Second)
	if nanos <= 0 {
		return 0, false, fmt.Errorf("ttl must be positive")
	}
	if nanos > float64(infiniteTTLDuration) {
		return 0, false, fmt.Errorf("ttl exceeds maximum supported duration of %s", infiniteTTLDuration)
	}
	return time.Duration(nanos), false, nil
}

func normalizeTTLUnit(unit string) string {
	trimmed := strings.TrimSpace(unit)
	trimmed = strings.Trim(trimmed, "().")
	return strings.ToLower(trimmed)
}

func isInfiniteKeyword(value string) bool {
	switch strings.ReplaceAll(value, " ", "") {
	case "0", "-1", "inf", "infinite", "infinity", "forever", "permanent", "never", "none", "unlimited", "noexpiry", "noexp", "perma", "infinitettl":
		return true
	default:
		return false
	}
}

func decodeSecretKey(input string) ([]byte, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, fmt.Errorf("secret key cannot be empty")
	}
	try := func(data []byte, err error) ([]byte, bool) {
		if err != nil {
			return nil, false
		}
		if token.ValidateKey(data) == nil {
			return data, true
		}
		return nil, false
	}
	base64Decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	}
	for _, dec := range base64Decoders {
		if b, ok := try(dec(trimmed)); ok {
			return b, nil
		}
	}
	if b, ok := try(hex.DecodeString(trimmed)); ok {
		return b, nil
	}
	if len(trimmed) == symmetricKeyLength {
		if b, ok := try([]byte(trimmed), nil); ok {
			return b, nil
		}
	}
	return nil, fmt.Errorf("secret key must decode to %d bytes", symmetricKeyLength)
}

func generateSecretKeyMaterial() (string, []byte, error) {
	buf := make([]byte, symmetricKeyLength)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("unable to generate secret key: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(buf), buf, nil
}

func processDecryption(config *Config) (*token.Token, error) {
	t, err := token.DecryptToken(config.TokenInput, config.SecretKeyBytes)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Token ID: %s\n", t.ID)
	fmt.Printf("Algorithm: %s\n", t.Header[token.HeaderAlg])
	if kid := t.Header[token.HeaderKeyID]; kid != "" {
		fmt.Printf("Key ID: %s\n", kid)
	}
	fmt.Printf("Issued At: %s\n", t.IssuedAt.Format(time.RFC3339))
	fmt.Printf("Not Before: %s\n", t.NotBefore.Format(time.RFC3339))
	fmt.Printf("Expires At: %s\n", t.ExpiresAt.Format(time.RFC3339))
	if t.IsExpired() {
		fmt.Println("Status: expired")
	} else {
		remaining := t.RemainingTTL()
		if remaining > 0 {
			fmt.Printf("Status: active (remaining TTL: %s)\n", remaining.Truncate(time.Second))
		} else {
			fmt.Println("Status: active")
		}
	}
	claimsJSON, err := json.MarshalIndent(t.Claims, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}
	fmt.Printf("Claims: %s\n", claimsJSON)
	if len(t.Footer) > 0 {
		footerJSON, err := json.MarshalIndent(t.Footer, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal footer: %w", err)
		}
		fmt.Printf("Footer: %s\n", footerJSON)
	}
	return t, nil
}

func copySecretToClipboard(secret string, verbose bool) {
	if secret == "" {
		return
	}
	if err := clipboard.WriteAll(secret); err != nil {
		if verbose {
			fmt.Printf("Warning: Unable to copy secret to clipboard: %v\n", err)
		}
		return
	}
	if verbose {
		fmt.Println("✓ Secret copied to clipboard")
	}
}

func detectFileType(filePath string) (string, error) {
	base := strings.ToLower(filepath.Base(filePath))
	ext := strings.ToLower(filepath.Ext(base))
	switch ext {
	case ".env":
		return "env", nil
	case ".json":
		return "json", nil
	case ".yaml":
		return "yaml", nil
	case ".yml":
		return "yml", nil
	case ".bcl":
		return "bcl", nil
	}
	if base == "env" || base == ".env" || strings.HasPrefix(base, ".env.") || strings.Contains(base, ".env.") {
		return "env", nil
	}
	return "", fmt.Errorf("unable to auto-detect file type for %s; please provide -t flag", filePath)
}

func createBackup(filePath string) error {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil // No backup needed for non-existent files
	}

	backupPath := filePath + ".bak"

	// Remove existing backup if it exists
	if _, err := os.Stat(backupPath); err == nil {
		if err := os.Remove(backupPath); err != nil {
			return fmt.Errorf("failed to remove old backup: %w", err)
		}
	}

	// Copy original file to backup
	sourceFile, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(backupPath)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer destFile.Close()

	// Copy contents
	if _, err := destFile.ReadFrom(sourceFile); err != nil {
		return fmt.Errorf("failed to copy file contents: %w", err)
	}

	return nil
}
