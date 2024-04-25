package turnstile

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"time"
)

type service struct {
	timeout      time.Duration
	secret       string
	backupSecret string
	url          string
}

func newService(config Config) Service {
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	return &service{
		secret:       config.Secret,
		backupSecret: config.BackupSecret,
		timeout:      config.Timeout,
		url:          "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	}
}

func (s *service) Verify(ctx context.Context, token string, ip string) (bool, error) {
	return s.verify(ctx, s.secret, token, ip, "")
}

func (s *service) VerifyIdempotent(ctx context.Context, token string, ip string, key string) (bool, error) {
	return s.verify(ctx, s.secret, token, ip, key)
}

func (s *service) RandomUUID() string {
	uuid := make([]byte, 16)
	_, _ = rand.Read(uuid)
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}

func (s *service) verify(ctx context.Context, secret string, token string, ip string, key string) (bool, error) {
	_, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("secret", secret)
	_ = writer.WriteField("response", token)
	_ = writer.WriteField("remoteip", ip)
	if key != "" {
		_ = writer.WriteField("idempotency_key", key)
	}
	_ = writer.Close()
	client := &http.Client{}
	req, _ := http.NewRequest("POST", s.url, body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	firstResult, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer firstResult.Body.Close()
	firstOutcome := make(map[string]interface{})
	err = json.NewDecoder(firstResult.Body).Decode(&firstOutcome)
	if err != nil {
		return false, err
	}
	if success, ok := firstOutcome["success"].(bool); ok && success {
		return true, nil
	}
	return false, nil
}

func (s *service) VerifyBackup(ctx context.Context, token string, ip string) (bool, error) {
	return s.verify(ctx, s.backupSecret, token, ip, "")
}

func (s *service) VerifyBackupIdempotent(ctx context.Context, token string, ip string, key string) (bool, error) {
	return s.verify(ctx, s.backupSecret, token, ip, key)
}

// Config is the configuration for the service.
type Config struct {
	// Secret is the secret key used to verify the token.
	// This is required.
	Secret string

	// BackupSecret is the backup secret key used to verify the token.
	// This is optional.
	BackupSecret string

	// Timeout is the timeout for the service.
	// This is optional.
	// Default: 10 seconds
	Timeout time.Duration
}

// Service is the interface for the service.
// It is used to verify the token.
// It is also used to generate a random UUID.
type Service interface {
	// Verify is used to verify the token.
	// It returns true if the token is valid.
	// It returns false if the token is invalid.
	// It returns an error if there was an error verifying the token.
	Verify(ctx context.Context, token string, ip string) (bool, error)

	// VerifyIdempotent is used to verify the token.
	// The key parameter is used to ensure idempotency.
	// You may use the RandomUUID method to generate a random UUID.
	// It returns true if the token is valid.
	// It returns false if the token is invalid.
	// It returns an error if there was an error verifying the token.
	VerifyIdempotent(ctx context.Context, token string, ip string, key string) (bool, error)

	// VerifyBackup is used to verify the token.
	// It returns true if the token is valid.
	// It returns false if the token is invalid.
	// It returns an error if there was an error verifying the token.
	VerifyBackup(ctx context.Context, token string, ip string) (bool, error)

	// VerifyBackupIdempotent is used to verify the token.
	// The key parameter is used to ensure idempotency.
	// You may use the RandomUUID method to generate a random UUID.
	// It returns true if the token is valid.
	// It returns false if the token is invalid.
	// It returns an error if there was an error verifying the token.
	VerifyBackupIdempotent(ctx context.Context, token string, ip string, key string) (bool, error)

	// RandomUUID is used to generate a random UUID.
	// It returns a random UUID.
	RandomUUID() string
}

// New is used to create a new service.
// It returns a new service.
func New(config Config) Service {
	return newService(config)
}
