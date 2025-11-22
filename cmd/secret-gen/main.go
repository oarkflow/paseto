package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/oarkflow/paseto/token"
)

const (
	version = "1.0.0"
)

type Config struct {
	FileType    string
	FilePath    string
	Key         string
	Length      int
	Force       bool
	Backup      bool
	Verbose     bool
	ShowVersion bool
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

	if err := runSecretGeneration(config); err != nil {
		log.Fatalf("Secret generation failed: %v", err)
	}

	if config.Verbose {
		fmt.Printf("✓ Successfully generated and set secret for key '%s' in %s\n", config.Key, config.FilePath)
	}
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.FileType, "type", "", "Configuration file type (env, json, yaml, yml, bcl)")
	flag.StringVar(&config.FileType, "t", "", "Configuration file type (env, json, yaml, yml, bcl) (shorthand)")
	flag.StringVar(&config.FilePath, "file", "", "Path to configuration file")
	flag.StringVar(&config.FilePath, "f", "", "Path to configuration file (shorthand)")
	flag.StringVar(&config.Key, "key", "", "Key name to set/update")
	flag.StringVar(&config.Key, "k", "", "Key name to set/update (shorthand)")
	flag.IntVar(&config.Length, "length", 32, "Length of the generated secret")
	flag.IntVar(&config.Length, "l", 32, "Length of the generated secret (shorthand)")
	flag.BoolVar(&config.Force, "force", false, "Force overwrite without confirmation")
	flag.BoolVar(&config.Backup, "backup", true, "Create backup of original file")
	flag.BoolVar(&config.Backup, "b", true, "Create backup of original file (shorthand)")
	noBackup := flag.Bool("no-backup", false, "Disable backup creation")
	flag.BoolVar(&config.Verbose, "verbose", true, "Enable verbose output")
	flag.BoolVar(&config.Verbose, "v", true, "Enable verbose output (shorthand)")
	showVersion := flag.Bool("version", false, "Show version information")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "paseto-secret v%s - Generate and set secrets in configuration files\n\n", version)
		fmt.Fprintf(os.Stderr, "USAGE:\n")
		fmt.Fprintf(os.Stderr, "  paseto-secret -t <type> -f <file> -k <key> [options]\n\n")
		fmt.Fprintf(os.Stderr, "EXAMPLES:\n")
		fmt.Fprintf(os.Stderr, "  paseto-secret -t env -f .env -k API_KEY\n")
		fmt.Fprintf(os.Stderr, "  paseto-secret -t json -f config.json -k api_key -l 64\n")
		fmt.Fprintf(os.Stderr, "  paseto-secret -t yaml -f config.yaml -k secret_key --no-backup\n\n")
		fmt.Fprintf(os.Stderr, "OPTIONS:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	config.ShowVersion = *showVersion

	// Handle no-backup flag
	if *noBackup {
		config.Backup = false
	}

	return config
}

func validateConfig(config *Config) error {
	if config.FileType == "" {
		return fmt.Errorf("file type is required (-t flag)")
	}

	if config.FilePath == "" {
		return fmt.Errorf("file path is required (-f flag)")
	}

	if config.Key == "" {
		return fmt.Errorf("key name is required (-k flag)")
	}

	if config.Length <= 0 {
		return fmt.Errorf("secret length must be positive")
	}

	if config.Length > 1024 {
		return fmt.Errorf("secret length cannot exceed 1024 characters")
	}

	// Validate file type
	validTypes := map[string]bool{
		"env":  true,
		"json": true,
		"yaml": true,
		"yml":  true,
		"bcl":  true,
	}

	if !validTypes[strings.ToLower(config.FileType)] {
		return fmt.Errorf("unsupported file type '%s'. Supported types: env, json, yaml, yml, bcl", config.FileType)
	}

	// Check if file exists (unless it's a new file)
	if _, err := os.Stat(config.FilePath); os.IsNotExist(err) {
		if config.Verbose {
			fmt.Printf("Warning: File '%s' does not exist, it will be created\n", config.FilePath)
		}
	}

	return nil
}

func runSecretGeneration(config *Config) error {
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
		return fmt.Errorf("unsupported file type: %s", fileType)
	}

	if err != nil {
		return fmt.Errorf("failed to update %s file: %w", fileType, err)
	}

	return nil
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
