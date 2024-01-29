package signature_plugin

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	rand2 "math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
)

type KeyBlob struct {
	RsaPrivateKey     *rsa.PrivateKey
	RsaPublicKey      *rsa.PublicKey
	Ed25519PrivateKey *ed25519.PrivateKey
	Ed25519PublicKey  *ed25519.PublicKey
}

type PlainKeys struct {
	PlainRSAPublic      string
	PlainRSAPrivate     string
	PlainED25519Public  string
	PlainED25519Private string
}

var letters = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

var keyBlob = &KeyBlob{}
var plainKeys = &PlainKeys{}

func Test1(t *testing.T) {
	GenerateKeys(plainKeys, keyBlob)
	// change this for tests
	config := PopulateConfig(
		true,
		true,
		true,
		false,
		true,
		-1,
		false,
		true,
		true,
		false,
		false,
		plainKeys,
	)
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, config, "signature-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	// change this for tests
	req := PopulateRequest(config, &ctx, 500, "application/json")

	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(recorder, req)
	mBuilder, err := buildMessage(req, config)
	if err != nil {
		t.Fatal(err)
	}
	if err1 := verifySignature(req, config, mBuilder); err1 != nil {
		t.Fatal(err1)
	}
}

func Test2(t *testing.T) {
	GenerateKeys(plainKeys, keyBlob)
	// change this for tests
	config := PopulateConfig(
		false,
		false,
		false,
		true,
		false,
		100,
		false,
		false,
		true,
		true,
		true,
		plainKeys,
	)
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, config, "signature-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	// change this for tests
	req := PopulateRequest(config, &ctx, 5000, "application/json")

	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(recorder, req)
	mBuilder, err := buildMessage(req, config)
	if err != nil {
		t.Fatal(err)
	}
	if err1 := verifySignature(req, config, mBuilder); err1 != nil {
		t.Fatal(err1)
	}
}

func Test3(t *testing.T) {
	GenerateKeys(plainKeys, keyBlob)
	// change this for tests
	config := PopulateConfig(
		false,
		false,
		false,
		true,
		false,
		-1,
		true,
		false,
		true,
		false,
		false,
		plainKeys,
	)
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, config, "signature-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	// change this for tests
	req := PopulateRequest(config, &ctx, 5000, "application/octet-stream")

	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(recorder, req)
	mBuilder, err := buildMessage(req, config)
	if err != nil {
		t.Fatal(err)
	}
	if err1 := verifySignature(req, config, mBuilder); err1 != nil {
		t.Fatal(err1)
	}
}

func buildMessage(req *http.Request, config *Config) (*strings.Builder, error) {
	mBuilder := strings.Builder{}
	construct := req.Header.Get(config.ConstructHeaderName)

	for _, s := range strings.Split(construct, ",") {
		switch s {
		case "th":
			mBuilder.WriteString(req.Header.Get(config.TimeHeaderName) + ",")
		case "m":
			mBuilder.WriteString(req.Method + ",")
		case "p":
			mBuilder.WriteString(req.URL.Path + ",")
		case "r1":
			if err := addHeaderToBuilder(req.Header, &mBuilder, "Accept"); err != nil {
				return nil, err
			}
		case "r2":
			if err := addHeaderToBuilder(req.Header, &mBuilder, "Accept-Charset"); err != nil {
				return nil, err
			}
		case "o1":
			if err := addHeaderToBuilder(req.Header, &mBuilder, "Cache-Control"); err != nil {
				return nil, err
			}
		case "o2":
			if err := addHeaderToBuilder(req.Header, &mBuilder, "Referer"); err != nil {
				return nil, err
			}

		case "ib", "nb", "ub", "sb", "eb":

		case "wb":
			b, _ := io.ReadAll(req.Body)
			mBuilder.WriteString(string(b))

		default:
			return nil, errors.New("untested handle")
		}

	}
	return &mBuilder, nil
}

func verifySignature(req *http.Request, config *Config, mBuilder *strings.Builder) error {
	nb := bytes.NewBufferString(mBuilder.String()).Bytes()
	sig, _ := hex.DecodeString(req.Header.Get(config.SignatureHeaderName))
	if config.KeyType == "rsa" && config.RSASignatureAlgo == "pcks1v15" {
		hashed := sha256.Sum256(nb)
		return rsa.VerifyPKCS1v15(&config.rsaKey.PublicKey, crypto.SHA256, hashed[:], sig)
	} else if config.KeyType == "rsa" && config.RSASignatureAlgo == "pss" {
		hashed := sha256.Sum256(nb)
		return rsa.VerifyPSS(&config.rsaKey.PublicKey, crypto.SHA256, hashed[:], sig, nil)
	} else if config.KeyType == "ed25519" {
		block, _ := pem.Decode([]byte(plainKeys.PlainED25519Public))
		key, _ := x509.ParsePKIXPublicKey(block.Bytes)
		res := ed25519.Verify(key.(ed25519.PublicKey), nb, sig)
		if !res {
			return errors.New("failed to verify ed25519")
		}
	}
	return nil
}

func PopulateRequest(
	config *Config,
	ctx *context.Context,
	contentLength int,
	contentType string,
) *http.Request {
	var body io.Reader = nil
	if contentLength > 0 {
		body = strings.NewReader(randSeq(contentLength))

	}
	req, _ := http.NewRequestWithContext(*ctx, http.MethodPost, "https://abc.de", body)
	if body != nil {
		req.Header.Set("Content-Length", strconv.Itoa(contentLength))
		req.Header.Set("Content-Type", "application/json")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	if len(config.RequiredHeaders) > 0 {
		req.Header.Add("Accept", "text/html")
		req.Header.Add("Accept", "application/json")

		req.Header.Set("Accept-Charset", "utf-8")
	}
	if len(config.OptionalHeaders) > 0 {
		req.Header.Set("Cache-Control", "max-age=0")
		req.Header.Set("Referer", "https://example.com/test.html")
	}
	if len(config.AdditionalHeaders) > 0 {
		for key, val := range config.AdditionalHeaders {
			req.Header.Set(key, val)
		}
	}

	return req
}

func PopulateConfig(
	signatureHeaderName bool,
	constructHeaderName bool,
	timeHeaderName bool,
	requiredHeaders bool,
	optionalHeaders bool,
	maxHashableContentLength int64,
	hashableContentTypes bool,
	additionalHeaders bool,
	rsaKey bool,
	pssAlgo bool,
	keyAsEnv bool,
	plainKeys *PlainKeys,
) *Config {

	config := CreateConfig()

	if signatureHeaderName {
		config.SignatureHeaderName = "X-Testing-Sig"
	}
	if constructHeaderName {
		config.ConstructHeaderName = "X-Testing-Con"
	}
	if timeHeaderName {
		config.TimeHeaderName = "X-Test-Time"
	}
	if requiredHeaders {
		config.RequiredHeaders = map[string]string{"r1": "Accept", "r2": "Accept-Charset"}
	}
	if optionalHeaders {
		config.OptionalHeaders = map[string]string{"o1": "Cache-Control", "o2": "Referer"}
	}

	config.MaxHashableContentLength = maxHashableContentLength

	if hashableContentTypes {
		config.HashableContentTypes = []string{"application/json"}
	}
	if additionalHeaders {
		config.AdditionalHeaders = map[string]string{"X-Additional-1": "Test1", "X-Additional-2": "Test2"}
	}
	if rsaKey {
		config.KeyType = "rsa"
	} else {
		config.KeyType = "ed25519"
	}
	if keyAsEnv {
		keyname := "testenv"
		config.KeyName = keyname
		if rsaKey {
			if err := os.Setenv(keyname, base64.URLEncoding.EncodeToString([]byte(plainKeys.PlainRSAPrivate))); err != nil {
				panic("can't set rsa-env")
			}

		} else {
			if err := os.Setenv(keyname, base64.URLEncoding.EncodeToString([]byte(plainKeys.PlainED25519Private))); err != nil {
				panic("can't set rsa-env")
			}
		}

	} else {
		if rsaKey {
			config.KeyValue = base64.URLEncoding.EncodeToString([]byte(plainKeys.PlainRSAPrivate))
		} else {
			config.KeyValue = base64.URLEncoding.EncodeToString([]byte(plainKeys.PlainED25519Private))
		}
	}
	if rsaKey && pssAlgo {
		config.RSASignatureAlgo = "pss"
	} else if rsaKey {
		config.RSASignatureAlgo = "pcks1v15"
	}
	return config
}

func GenerateKeys(plainKeys *PlainKeys, keyBlob *KeyBlob) {
	bitSize := 4096

	k1, _ := rsa.GenerateKey(rand.Reader, bitSize)
	keyBlob.RsaPrivateKey = k1
	keyBlob.RsaPublicKey = &k1.PublicKey

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyBlob.Ed25519PublicKey = &pub
	keyBlob.Ed25519PrivateKey = &priv

	plainKeys.PlainRSAPublic = string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&k1.PublicKey),
		},
	))

	plainKeys.PlainRSAPrivate = string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k1),
		},
	))
	b, _ := x509.MarshalPKIXPublicKey(pub)

	plainKeys.PlainED25519Public = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	}))

	b, _ = x509.MarshalPKCS8PrivateKey(priv)

	plainKeys.PlainED25519Private = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}))

}

// stolen this from stackoverflow

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand2.Intn(len(letters))]
	}
	return string(b)
}
