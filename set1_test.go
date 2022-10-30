package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
)

func TestHex2B64(t *testing.T) {
	res := Hex2B64(hex2bytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
	fmt.Println(string(res))
}

func TestFixedXOR(t *testing.T) {
	res := FixedXOR(hex2bytes("1c0111001f010100061a024b53535009181c"), hex2bytes("686974207468652062756c6c277320657965"))
	fmt.Println(string(res))
}

func TestSingleByteXOR(t *testing.T) {
	res, key := SingleByteXOR(hex2bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
	fmt.Println(string(res), string(key))
}

func TestDetectSingleByteXOR(t *testing.T) {
	dat, err := os.ReadFile("./challenge-data/4.txt")
	if err != nil {
		log.Fatal("can't open a file", err)
	}

	param := make([][]byte, 0)
	for _, s := range strings.Split(string(dat), "\n") {
		param = append(param, hex2bytes(s))
	}

	fmt.Printf("the key is: %d\n", DetectSingleByteXOR(param))
}

func TestRepeatingKeyXOR(t *testing.T) {
	res := RepeatingKeyXOR([]byte("dils.matchanov@gmail.com"), []byte("shisui"))
	fmt.Println(bytes2hex(res))
}

func TestBreakRepeatingXOR(t *testing.T) {
	datb64, err := os.ReadFile("./challenge-data/6.txt")
	if err != nil {
		log.Fatal("can't open a file", err)
	}

	dat := make([]byte, base64.StdEncoding.DecodedLen(len(datb64)))
	if _, err := base64.StdEncoding.Decode(dat, datb64); err != nil {
		t.Logf("can't decode base64 bytes: %s\n", err.Error())
		t.FailNow()
	}

	key := BreakRepeatingXOR(dat)
	fmt.Println(string(RepeatingKeyXOR(dat, key)))
}

func TestECBDecrypt(t *testing.T) {
	datb64, err := os.ReadFile("./challenge-data/7.txt")
	if err != nil {
		log.Fatal("can't open a file", err)
	}

	dat := make([]byte, base64.StdEncoding.DecodedLen(len(datb64)))
	if _, err := base64.StdEncoding.Decode(dat, datb64); err != nil {
		log.Fatal("can't decode base64", err)
	}

	res := ECBDecrypt(dat, []byte("YELLOW SUBMARINE"))
	fmt.Println(string(res))
}

func TestHammingDistance(t *testing.T) {
	fmt.Println(hammingDistance([]byte("this is a test"), []byte("wokka wokka!!!")))
}

func TestBytesToBits(t *testing.T) {
	fmt.Println(bytesToBits([]byte("1")))
}

func TestCharDistance(t *testing.T) {
	a := "dHHLNI@jdTKNLBFWHRICHAEFDHI"
	fmt.Println(charDistance(computeCharFreqForString(a)))
}

func hex2bytes(s string) []byte {
	res, _ := hex.DecodeString(s)
	return res
}

func bytes2hex(s []byte) string {
	return hex.EncodeToString(s)
}

func TestCrack(t *testing.T) {
	dmsg := hex2bytes("243a2b282e20203021202f36")
	fmt.Println(hammingDistance(dmsg[:3], dmsg[3:6]) / 3)
	fmt.Println(hammingDistance(dmsg[:2], dmsg[2:4]) / 2)
	fmt.Println(hammingDistance(dmsg[:4], dmsg[4:8]) / 4)
}
