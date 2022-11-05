package cryptopals

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"reflect"
	"testing"
)

func TestPKCSPadding(t *testing.T) {
	if l := len(padding([]byte("YELLOW SUBMARINE"), 20)); l != 20 {
		t.Fatalf("length must be 20, but got %d", l)
	}
}

func TestCBCEncrypt(t *testing.T) {
	res, _ := CBCEncrypt([]byte("some large large text"), []byte("some"), []byte("YELLOW SUBMARINE"))
	fmt.Println(bytes2hex(res))
}

func TestCBCDecrypt(t *testing.T) {
	datb64, err := os.ReadFile("./challenge-data/10.txt")
	if err != nil {
		log.Fatal("can't open a file", err)
	}

	dat := make([]byte, base64.StdEncoding.DecodedLen(len(datb64)))
	n, err := base64.StdEncoding.Decode(dat, datb64)
	if err != nil {
		log.Fatal("can't decode base64", err)
	}

	dat = dat[:n]

	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	key := []byte("YELLOW SUBMARINE")

	res := CBCDecrypt(dat, iv, key)
	fmt.Println(string(res))
}

func TestECBEncrypt(t *testing.T) {
	msg := []byte("YELLOW SUBMARINEYELLOW SUBMARINE")
	key := []byte("YELLOW SUBMARINE")
	if res := ECBDecrypt(ECBEncrypt(msg, key), key); !reflect.DeepEqual(res, msg) {
		t.Fatal("invalid result of decryption", string(res))
	}
}

func TestDetectECBORCBC(t *testing.T) {
	var ecb, cbc int
	for i := 0; i < 1000; i++ {
		msg := ECBORCBCEncrypt(bytes.Repeat([]byte{16}, 16*3))
		if DetectECB([][]byte{msg}) != nil {
			ecb++
		} else {
			cbc++
		}
	}

	fmt.Println(ecb, cbc)
}
