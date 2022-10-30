package cryptopals

import (
	"fmt"
	"reflect"
	"testing"
)

func TestPKCSPadding(t *testing.T) {
	if l := len(padding([]byte("YELLOW SUBMARINE"), 20)); l != 20 {
		t.Fatalf("length must be 20, but got %d", l)
	}
}

func TestCBCEncrypt(t *testing.T) {
	res, _ := CBCEncrypt([]byte("shisui"), []byte("some"), []byte("YELLOW SUBMARINE"))
	fmt.Println(bytes2hex(res))
}

func TestCBCDecrypt(t *testing.T) {
	msg := []byte("shisui")
	iv := []byte("some")
	key := []byte("YELLOW SUBMARINE")

	text, _ := CBCEncrypt(msg, iv, key)
	if res := CBCDecrypt(text, iv, key); !reflect.DeepEqual(res, msg) {
		t.Fatal("invalid result of decryption", string(res)) // TODO: fails coz I need to remove padding in decryption
	}
}

func TestECBEncrypt(t *testing.T) {
	msg := []byte("YELLOW SUBMARINEYELLOW SUBMARINE")
	key := []byte("YELLOW SUBMARINE")
	if res := ECBDecrypt(ECBEncrypt(msg, key), key); !reflect.DeepEqual(res, msg) {
		t.Fatal("invalid result of decryption", string(res))
	}
}
