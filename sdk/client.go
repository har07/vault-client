package sdk

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/parnurzeal/gorequest"
	"github.com/pkg/errors"
)

// Client provide abstraction for data that managed at secret server such as Vault
type Client struct {
	Address string
	Token   string
	BaseDir string
	Verbose bool
}

// Secret is
type Secret map[string]string

// SecretResponse is
type SecretResponse struct {
	RequestID     string      `json:"request_id"`
	LeaseID       string      `json:"lease_id"`
	Renewable     bool        `json:"renewable"`
	LeaseDuration int         `json:"lease_duration"`
	Data          Secret      `json:"data"`
	WrapInfo      interface{} `json:"wrap_info"`
	Warnings      interface{} `json:"warnings"`
	Auth          interface{} `json:"auth"`
}

// SignedKey is
type SignedKey struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		SerialNumber string `json:"serial_number"`
		SignedKey    string `json:"signed_key"`
	} `json:"data"`
	WrapInfo interface{} `json:"wrap_info"`
	Warnings interface{} `json:"warnings"`
	Auth     interface{} `json:"auth"`
}

// NewClient return new Client client
func NewClient(address, token, baseDir string) *Client {
	return &Client{
		Address: address,
		Token:   token,
		BaseDir: baseDir,
	}
}

func (s *Client) prepareRequest(method, path string, skipBaseDir ...bool) *gorequest.SuperAgent {
	url := s.Address + s.BaseDir + path
	if len(skipBaseDir) > 0 && skipBaseDir[0] {
		url = s.Address + path
	}
	if s.Verbose {
		fmt.Printf("secret endpoint: %s\n", url)
	}
	return gorequest.New().CustomMethod(method, url).Set("x-vault-token", s.Token)
}

// ReadSecret return decrypted secret from storage
func (s *Client) ReadSecret(path string) (secret *SecretResponse, err error) {
	req := s.prepareRequest("GET", path)
	resp, body, errs := req.End()

	if errs != nil {
		return nil, fmt.Errorf("get secret from storage failed: %s", errs[0].Error())
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("Get secret status is %d", resp.StatusCode)
	}

	secret = &SecretResponse{}
	err = json.Unmarshal([]byte(body), &secret)
	if err != nil {
		return nil, fmt.Errorf("parse secret failed: %s", err.Error())
	}
	return secret, nil
}

// SaveSecret store encrypted secret in storage
func (s *Client) SaveSecret(path string, secret Secret) (err error) {
	req := s.prepareRequest("POST", path).SendStruct(secret)
	resp, body, errs := req.End()

	if errs != nil {
		return fmt.Errorf("save secret to storage failed: %s", errs[0].Error())
	}

	if resp.StatusCode != http.StatusNoContent {
		return errors.Errorf("Save secret status is %d: %s", resp.StatusCode, body)
	}

	return nil
}

// DeleteSecret delete secret from storage
func (s *Client) DeleteSecret(path string) (err error) {
	req := s.prepareRequest("DELETE", path)
	resp, body, errs := req.End()

	if errs != nil {
		return fmt.Errorf("delete secret from storage failed: %s", errs[0].Error())
	}

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("Delete secret status is %d: %s", resp.StatusCode, body)
	}

	return nil
}

// HealthCheck is
func (s *Client) HealthCheck() (err error) {
	req := gorequest.New().Get(s.Address+"/sys/health").Timeout(10*time.Second).Set("x-vault-token", s.Token)
	resp, body, errs := req.End()
	if errs != nil {
		return fmt.Errorf("secret storage health check failed: %s", errs[0].Error())
	}

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("secret storage health check status is %d: %s", resp.StatusCode, body)
	}

	return nil
}

// GetSignedPublicKey return temporary signed public key for SSH
func (s *Client) GetSignedPublicKey(path, plainPublicKey string) (pubKey *SignedKey, err error) {
	payload := map[string]string{
		"public_key": plainPublicKey,
	}
	req := s.prepareRequest("POST", path, true).Send(payload)
	resp, body, errs := req.End()

	if errs != nil {
		return nil, fmt.Errorf("get signed public key from storage failed: %s", errs[0].Error())
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("Get signed public key status is %d", resp.StatusCode)
	}

	pubKey = &SignedKey{}
	err = json.Unmarshal([]byte(body), &pubKey)
	if err != nil {
		return nil, fmt.Errorf("parse signed public key response failed: %s", err.Error())
	}
	return pubKey, nil
}
