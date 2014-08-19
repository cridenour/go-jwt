package jwt

import (
	"encoding/base64"
	"io/ioutil"
	"strings"
	"testing"
)

func TestHS256Encode(t *testing.T) {
	specKey := []byte{3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163}

	payload := map[string]interface{}{
		"iss": "joe",
		"exp": 1300819380,
		"http://example.com/is_root": true,
	}

	ret, _ := EncodeHS256(payload, specKey)

	parts := strings.Split(ret, ".")

	// UPDATED: Go marshals JSON a bit differently than the spec
	if parts[0] != "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" {
		t.Error("Mismatch in header.")
		decoded, _ := base64.URLEncoding.DecodeString(parts[0])
		t.Error(string(decoded))
	}

	if parts[1] != "eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ" {
		t.Error("Mismatch from spec in payload.")
		decoded, _ := base64.URLEncoding.DecodeString(parts[1])
		t.Error(string(decoded))
	}

	if parts[2] != "tu77b1J0ZCHMDd3tWZm36iolxZtBRaArSrtayOBDO34" {
		t.Error("Mismatch from spec in crypto.")
		t.Error(parts[2])
	}

}

func TestHS256Decode(t *testing.T) {
	data := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.tu77b1J0ZCHMDd3tWZm36iolxZtBRaArSrtayOBDO34"

	specKey := []byte{3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163}

	payload := Decode(data, specKey)

	joe := payload["iss"].(string)
	if joe != "joe" {
		t.Error("Did not decode correctly.")
	}
}

func TestRS512Encode(t *testing.T) {
	// Payload from the spec
	payload := map[string]interface{}{
		"iss": "joe",
		"exp": 1300819380,
		"http://example.com/is_root": true,
	}

	// Load our private key from file
	rsaKey, _ := ioutil.ReadFile("test_private.pem")

	ret, _ := EncodeRS512(payload, rsaKey)

	_ = strings.Split(ret, ".")
}

func TestRS512Decode(t *testing.T) {
	data := "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.QFyWTPV0SB4D3-mwKphSJzX0A6mlB0fEo0aDgI2Hn6RbbUXg0303N7Jblf6xBzpGJ6wG1RDmkgf35TkQWB21ydWtJbPtwWboLl-Cq5nwn9mpvkKc_qAtvJtuUVNflHZ3tGuuKQ7-RvJbFQb5y9oGUq6-q6DYzT2uKfPrwtH6rSo"

	pubKey, _ := ioutil.ReadFile("test_public.pem")

	payload := Decode(data, pubKey)

	joe := payload["iss"].(string)
	t.Error(joe + joe)
}
