package signature_plugin

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"os"
)

func readKey(config *Config) error {
	defer func() {
		if err := recover(); err != nil {
			log.Println("error on key parsing:", err)
		}
	}()
	if config.KeyType == "rsa" && len(config.KeyName) > 0 {
		decoded, _ := base64.URLEncoding.DecodeString(os.Getenv(config.KeyName))
		block, _ := pem.Decode(decoded)
		key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
		config.rsaKey = *key

	} else if config.KeyType == "rsa" {
		decoded, _ := base64.URLEncoding.DecodeString(config.KeyValue)
		block, _ := pem.Decode(decoded)
		key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
		config.rsaKey = *key
	} else if config.KeyType == "ed25519" && len(config.KeyName) > 0 {
		decoded, _ := base64.URLEncoding.DecodeString(os.Getenv(config.KeyName))
		block, _ := pem.Decode(decoded)
		key, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
		config.edKey = key.(ed25519.PrivateKey)
	} else if config.KeyType == "ed25519" {
		decoded, _ := base64.URLEncoding.DecodeString(config.KeyValue)
		block, _ := pem.Decode(decoded)
		key, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
		config.edKey = key.(ed25519.PrivateKey)

	} else {
		return errors.New("problem parsing key, check config and key")
	}

	return nil
}

func printStuff(v any) {
	b, _ := json.Marshal(v)
	os.Stdout.WriteString("\n" + string(b) + "\n")
}
