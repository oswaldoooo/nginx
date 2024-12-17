package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestGenKeypairs(t *testing.T) {
	pub, pri, _ := ed25519.GenerateKey(rand.Reader)
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	fmt.Println(base64.StdEncoding.EncodeToString(pri))
}

const pubkey = `hrku5C8tCLCCLM41IKYVvJF7tPH2qUEKlQtjAG96kzs=`

func TestAntiLeechRequest(t *testing.T) {
	const prikey = `KhI282h4hZMzOiXGs7OXuTiSbiCdc6WIcry2t0tS+ZeGuS7kLy0IsIIszjUgphW8kXu08fapQQqVC2MAb3qTOw==`
	var (
		uri    = "/index.nginx-debian.html"
		tim    = strconv.FormatInt(time.Now().Add(time.Second*10).Unix(), 10)
		client = http.Client{}
	)
	content, err := base64.StdEncoding.DecodeString(prikey)
	if err != nil {
		t.Fatal(err)
	}
	pkey := ed25519.PrivateKey(content)
	content = ed25519.Sign(pkey, []byte(uri+tim))
	req, _ := http.NewRequest(http.MethodGet, "http://localhost"+uri, nil)
	query := req.URL.Query()
	query.Set("sign", base64.URLEncoding.EncodeToString(content))
	query.Set("time", tim)
	req.URL.RawQuery = query.Encode()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Log(base64.StdEncoding.EncodeToString(content))
		t.Log(content)
		t.Log(uri + tim)
		t.Fatal("bad response " + resp.Status)
	}
}
func TestAntiLeechRequestTimeout(t *testing.T) {
	const prikey = `KhI282h4hZMzOiXGs7OXuTiSbiCdc6WIcry2t0tS+ZeGuS7kLy0IsIIszjUgphW8kXu08fapQQqVC2MAb3qTOw==`
	var (
		uri    = "/index.nginx-debian.html"
		tim    = strconv.FormatInt(time.Now().Add(-time.Second*10).Unix(), 10)
		client = http.Client{}
	)
	content, err := base64.StdEncoding.DecodeString(prikey)
	if err != nil {
		t.Fatal(err)
	}
	pkey := ed25519.PrivateKey(content)
	content = ed25519.Sign(pkey, []byte(uri+tim))
	req, _ := http.NewRequest(http.MethodGet, "http://localhost"+uri, nil)
	query := req.URL.Query()
	query.Set("sign", base64.URLEncoding.EncodeToString(content))
	query.Set("time", tim)
	req.URL.RawQuery = query.Encode()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Log(base64.StdEncoding.EncodeToString(content))
		t.Log(content)
		t.Log(uri + tim)
		t.Fatal("bad response " + resp.Status)
	}
}
func TestDecodeBase64(t *testing.T) {
	content, err := base64.StdEncoding.DecodeString(`umUi+byCSYxiDmQzhZxXjCvZ7xyECUdjZotpYM0Sg5Y4LsoSV73ki9AajNVzT2I_uJmW9vFcB+pKMdB3soE1BQ%3D%3D`)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(content))
}
