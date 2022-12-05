package cryptopals

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPKCSPadding(t *testing.T) {
	if l := len(padding([]byte("YELLOW SUBMARINE"), 20)); l != 20 {
		t.Fatalf("length must be 20, but got %d", l)
	}
}

func TestCBCEncrypt(t *testing.T) {
	var (
		msg = []byte("some large large text")
		iv  = []byte("some")
		key = []byte("YELLOW SUBMARINE")
	)

	cipher, _ := CBCEncrypt(msg, iv, key)

	res := CBCDecrypt(cipher, iv, key)
	if !cmp.Equal(res, msg) {
		log.Fatalf("invalid decrypt output: %s - %s", string(msg), string(res))
	}

	fmt.Println(string(res))
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
	if res := ECBDecrypt(ECBEncrypt(msg, key), key); !cmp.Equal(res, msg) {
		t.Fatal("invalid result of decryption", string(res))
	}
}

func TestECBEncrypt2(t *testing.T) {
	res := ECBEncrypt(bytes.Repeat([]byte("1"), 16*3), generateAESKey())
	fmt.Println(len(res))
	for _, v := range chunkBy(res, 16) {
		fmt.Println(v)
	}
}

func TestDetectECBORCBC(t *testing.T) {
	var ecb, cbc int
	for i := 0; i < 1000; i++ {
		msg := ECBORCBCEncrypt(bytes.Repeat([]byte{16}, 16*3))
		if DetectECB(msg) {
			ecb++
		} else {
			cbc++
		}
	}

	fmt.Println(ecb, cbc)
}

func TestByteAtTimeECBDecrypter(t *testing.T) {
	fmt.Println(string(ByteAtTimeECBDecrypter()))
}
