package signature_plugin

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type IncludedHeaders struct {
}

type Config struct {
	rsaKey                   rsa.PrivateKey
	edKey                    ed25519.PrivateKey
	SignatureHeaderName      string            `yaml:"signatureHeaderName,omitempty"`
	ConstructHeaderName      string            `yaml:"constructHeaderName,omitempty"`
	TimeHeaderName           string            `yaml:"timeHeaderName,omitempty"`
	PathRegex                []string          `yaml:"pathRegex,omitempty"`
	AdditionalHeaders        map[string]string `yaml:"additionalHeaders,omitempty"`
	RequiredHeaders          map[string]string `yaml:"requiredHeaders,omitempty"`
	OptionalHeaders          map[string]string `yaml:"optionalHeaders,omitempty"`
	MaxHashableContentLength int64             `yaml:"maxHashableContentLength,omitempty"`
	HashableContentTypes     []string          `yaml:"hashableContentTypes,omitempty"`
	KeyName                  string            `yaml:"keyName,omitempty"`
	KeyType                  string            `yaml:"keyType,omitempty"`
	KeyValue                 string            `yaml:"keyValue,omitempty"`
	RSASignatureAlgo         string            `yaml:"rsaSignatureAlgo,omitempty"`
	ErrorStatus              int               `yaml:"errorStatus,omitempty"`
	ErrorMessage             bool              `yaml:"errorMessage,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		SignatureHeaderName:      "X-Test-Signature",
		ConstructHeaderName:      "X-Test-Construct",
		ErrorStatus:              http.StatusBadRequest,
		ErrorMessage:             true,
		MaxHashableContentLength: -1,
	}
}

type Signing struct {
	next   http.Handler
	name   string
	config Config
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	err := readKey(config)
	if err != nil {
		return nil, err
	}

	return &Signing{
		next:   next,
		name:   name,
		config: *config,
	}, nil

}

func (e *Signing) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	if isExcludedPath(req, &e.config) {
		e.next.ServeHTTP(rw, req)
		return
	}

	var cBuilder strings.Builder // construct builder
	var mBuilder strings.Builder // message builder

	setTimeHeader(req, &e.config, &cBuilder, &mBuilder)

	processBasics(req, &cBuilder, &mBuilder)

	addAdditionalHeaders(req, &e.config)

	if err := processRequiredHeaders(req, &e.config, &cBuilder, &mBuilder); err != nil {
		handleError(rw, err, &e.config)
		return
	}
	processOptionalHeaders(req, &e.config, &cBuilder, &mBuilder)

	if err := processBody(req, &e.config, &cBuilder, &mBuilder); err != nil {
		handleError(rw, err, &e.config)
		return
	}
	if err := signRequest(req, &e.config, &cBuilder, &mBuilder); err == nil {
		e.next.ServeHTTP(rw, req)
	} else {
		handleError(rw, err, &e.config)
	}

}

func setTimeHeader(req *http.Request, config *Config, cBuilder *strings.Builder, mBuilder *strings.Builder) {
	if len(config.TimeHeaderName) > 0 {
		currTime := time.Now().UTC().Format(time.RFC3339Nano)
		req.Header.Set(config.TimeHeaderName, currTime)
		cBuilder.WriteString("th" + ",")
		mBuilder.WriteString(currTime + ",")
	}

}

func isExcludedPath(req *http.Request, config *Config) bool {
	for _, reg := range config.PathRegex {
		exp := regexp.MustCompile(reg)
		if exp.MatchString(req.URL.Path) {
			return true
		}
	}
	return false
}

func addAdditionalHeaders(req *http.Request, config *Config) {
	for k, v := range config.AdditionalHeaders {
		req.Header.Set(k, v)
	}
}

func processBasics(req *http.Request, cBuilder *strings.Builder, mBuilder *strings.Builder) {

	mBuilder.WriteString(req.Method + ",")
	cBuilder.WriteString("m" + ",")

	mBuilder.WriteString(req.URL.Path + ",")
	cBuilder.WriteString("p" + ",")

}

func processRequiredHeaders(req *http.Request, config *Config, cBuilder *strings.Builder, mBuilder *strings.Builder) error {
	for short, headerName := range config.RequiredHeaders {
		if err := addHeaderToBuilder(req.Header, mBuilder, headerName); err != nil {
			return err
		}
		cBuilder.WriteString(short + ",")
	}
	return nil
}

func processOptionalHeaders(req *http.Request, config *Config, cBuilder *strings.Builder, mBuilder *strings.Builder) {
	for short, headerName := range config.OptionalHeaders {
		if err := addHeaderToBuilder(req.Header, mBuilder, headerName); err != nil {
			continue
		}
		cBuilder.WriteString(short + ",")
	}
}

func processBody(req *http.Request, config *Config, cBuilder *strings.Builder, mBuilder *strings.Builder) error {

	if config.MaxHashableContentLength == 0 {
		cBuilder.WriteString("ib") // ignore body
	} else if req.Body == http.NoBody {
		cBuilder.WriteString("nb") // no req.body present
	} else if req.ContentLength == -1 {

		cBuilder.WriteString("ub") // req.body unknown body, stream or some shit

	} else if config.MaxHashableContentLength >= req.ContentLength ||
		config.MaxHashableContentLength == -1 {

		if len(config.HashableContentTypes) > 0 && !headerContains(req.Header, "Content-Type", config.HashableContentTypes) {
			cBuilder.WriteString("sb") // skip body
		} else if b, err := io.ReadAll(req.Body); err == nil {

			mBuilder.WriteString(string(b))
			cBuilder.WriteString("wb") // with body
			req.Body = io.NopCloser(bytes.NewBuffer(b))

		} else {
			return errors.New("error reading req.Body")
		}

	} else {
		cBuilder.WriteString("eb") // enormous body
	}

	return nil
}

func signRequest(req *http.Request, config *Config, cBuilder *strings.Builder, mBuilder *strings.Builder) error {
	nb := bytes.NewBufferString(mBuilder.String()).Bytes()

	var signature []byte
	var err error
	if config.KeyType == "rsa" && config.RSASignatureAlgo == "pcks1v15" {
		hashed := sha256.Sum256(nb)
		signature, err = rsa.SignPKCS1v15(rand.Reader, &config.rsaKey, crypto.SHA256, hashed[:])
	} else if config.KeyType == "rsa" && config.RSASignatureAlgo == "pss" {
		hashed := sha256.Sum256(nb)
		signature, err = rsa.SignPSS(rand.Reader, &config.rsaKey, crypto.SHA256, hashed[:], nil)
	} else if config.KeyType == "ed25519" {
		signature = ed25519.Sign(config.edKey, nb)
	}
	if err != nil {
		return err
	}

	req.Header.Set(config.SignatureHeaderName, hex.EncodeToString(signature[:]))
	req.Header.Set(config.ConstructHeaderName, cBuilder.String())
	return nil
}

func addHeaderToBuilder(header http.Header, mBuilder *strings.Builder, key string) error {
	values := header.Values(http.CanonicalHeaderKey(key))
	if len(values) > 0 {
		for _, v := range values {
			mBuilder.WriteString(v + ",")
		}
		return nil
	}
	return errors.New(fmt.Sprintf("no values present for Header: %s", key))
}

func headerContains(header http.Header, key string, values []string) bool {
	for _, headerValues := range header.Values(http.CanonicalHeaderKey(key)) {
		for _, val := range values {
			if val == headerValues {
				return true
			}
		}

	}
	return false
}

func handleError(rw http.ResponseWriter, err error, config *Config) {
	if config.ErrorMessage {
		http.Error(rw, err.Error(), config.ErrorStatus)

	} else {
		http.Error(rw, "", config.ErrorStatus)
	}
}
