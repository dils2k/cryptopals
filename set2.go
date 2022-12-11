package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	mathrand "math/rand"
	"reflect"
	"strings"
	"time"
)

func padding(msg []byte, blen int) []byte {
	var res []byte
	for i := 0; i < blen; i++ {
		if i < len(msg) {
			res = append(res, msg[i])
		} else {
			res = append(res, byte('\x04'))
		}
	}
	return res
}

func CBCEncrypt(msg, iv, key []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("key length must be 16")
	}

	if len(iv) == 0 {
		return nil, errors.New("iv must not be nil")
	}

	resBlocks := make([][]byte, 0)
	blocks := chunkBy(msg, 16)
	for i, b := range blocks {
		b = padding(b, 16)
		if i == 0 {
			b = RepeatingKeyXOR(b, iv)
		} else {
			b = RepeatingKeyXOR(b, resBlocks[i-1])
		}
		resBlocks = append(resBlocks, ECBEncrypt(b, key))
	}

	var res []byte
	for _, b := range resBlocks {
		res = append(res, b...)
	}

	return res, nil
}

func CBCDecrypt(text, iv, key []byte) []byte {
	blocks := chunkBy(text, 16)

	resBlocks := make([][]byte, 0)
	for i, b := range blocks {
		b = ECBDecrypt(b, key)
		if i == 0 {
			b = RepeatingKeyXOR(b, iv)
		} else {
			b = RepeatingKeyXOR(b, blocks[i-1])
		}
		resBlocks = append(resBlocks, b)
	}

	var res []byte
	for i, b := range resBlocks {
		for _, bb := range b {
			if i == len(resBlocks)-1 && bb == 4 {
				continue // ignore padding
			}
			res = append(res, bb)
		}
	}

	return res
}

func ECBEncrypt(msg, key []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	encryptedBlocks := make([][]byte, 0)
	blocks := chunkBy(msg, cipher.BlockSize())
	for i, b := range blocks {
		encryptedBlocks = append(encryptedBlocks, make([]byte, cipher.BlockSize()))
		cipher.Encrypt(encryptedBlocks[i], padding(b, cipher.BlockSize()))
	}

	var encrypted []byte
	for _, b := range encryptedBlocks {
		encrypted = append(encrypted, b...)
	}

	return encrypted
}

func generateAESKey() []byte {
	res := make([]byte, 16)
	rand.Read(res)
	return res
}

func ECBORCBCEncrypt(msg []byte) []byte {
	key := generateAESKey()

	randappendNum := mathrand.Intn(5) + 5
	randappend := make([]byte, randappendNum)
	for i := 0; i < randappendNum; i++ {
		randappend[i] = byte(mathrand.Intn(256))
	}

	msg = append(randappend, append(msg, randappend...)...)

	var encrypted []byte
	if mathrand.Intn(2) == 0 {
		encrypted = ECBEncrypt(msg, key)
	} else {
		encrypted, _ = CBCEncrypt(msg, []byte{0}, key)
	}

	return encrypted
}

func ECBCipher() func([]byte) []byte {
	bs64append := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
		"YnkK"

	plainAppend, _ := base64.StdEncoding.DecodeString(bs64append)

	key := generateAESKey()
	randAppend := make([]byte, mathrand.Intn(5)+5)
	rand.Read(randAppend)

	return func(msg []byte) []byte {
		msg = append(msg, plainAppend...)
		return ECBEncrypt(append(randAppend, append(msg, randAppend...)...), key)
	}
}

func ByteAtTimeECBDecrypter() []byte {
	encrypt := ECBCipher()

	var (
		b = []byte("0")

		firstLen         = len(encrypt(b))
		blocksize        = 0
		secondBlockStart = 0
	)

	for i := 2; ; i++ {
		if len(encrypt(bytes.Repeat(b, i))) > firstLen && secondBlockStart == 0 {
			secondBlockStart = i
		}

		if len(encrypt(bytes.Repeat(b, i))) > len(encrypt(bytes.Repeat(b, secondBlockStart))) && secondBlockStart != 0 {
			blocksize = i - secondBlockStart
			break
		}
	}

	if !DetectECB(encrypt(bytes.Repeat(b, 100))) {
		panic("ecb was not detected")
	}

	var (
		appendBlocks   = len(chunkBy(encrypt([]byte{}), blocksize))
		alignBytes     = bytes.Repeat(b, blocksize*2)
		idenBlockIndex int
		found          bool
	)

	for {
		idenBlockIndex, found = finddup(chunkBy(encrypt(alignBytes), blocksize))
		if found {
			break
		}
		alignBytes = append(alignBytes, b...)
	}

	var (
		m                    = bytes.Repeat(b, blocksize*appendBlocks+len(alignBytes)+blocksize)
		controlledBlockIndex = appendBlocks + idenBlockIndex + 1
		decrypted            = make([]byte, 0)
	)

	for {
		m = m[1:]

		cipher := encrypt(m)
		if len(chunkBy(cipher, blocksize))-1 < controlledBlockIndex {
			break
		}

		allpos := make(map[string]byte)
		for i := 0; i < 255; i++ {
			plain := append(m, append(decrypted, byte(i))...)
			ciphertext := encrypt(plain)
			controlledBlock := chunkBy(ciphertext, blocksize)[controlledBlockIndex]
			allpos[string(controlledBlock)] = byte(i)
		}

		controlledBlock := chunkBy(cipher, blocksize)[controlledBlockIndex]
		b, ok := allpos[string(controlledBlock)]
		if !ok {
			panic("can't find byte")
		}

		decrypted = append(decrypted, b)
	}

	return decrypted
}

func finddup[T any](a []T) (int, bool) {
	for i := 1; i < len(a); i++ {
		if reflect.DeepEqual(a[i], a[i-1]) {
			return i, true
		}
	}
	return 0, false
}

func ParseKV(msg []byte) map[string]string {
	res := make(map[string]string)
	for _, kvs := range strings.Split(string(msg), "&") {
		kv := strings.Split(kvs, "=")
		if len(kv) < 2 {
			continue
		}
		res[kv[0]] = kv[1]
	}
	return res
}

func EncodeKV(in map[string]string) []byte {
	validated := make(map[string]string)
	for k, v := range in {
		v = strings.ReplaceAll(strings.ReplaceAll(v, "&", ""), "=", "")
		validated[k] = v
	}
	return []byte(fmt.Sprintf("email=%s&uid=%s&role=%s", in["email"], in["uid"], in["role"]))
}

func NewProfileFor() (func(name []byte) []byte, func(msg []byte) []byte) {
	key := generateAESKey()

	encrypt := func(name []byte) []byte {
		kv := EncodeKV(map[string]string{
			"email": string(name),
			"uid":   "10",
			"role":  "user",
		})
		return ECBEncrypt(kv, key)
	}

	decrypt := func(cipher []byte) []byte {
		return ECBDecrypt(cipher, key)
	}

	return encrypt, decrypt
}

func CrackProfileFor() {
	profileFor, decrypt := NewProfileFor()

	cipher := profileFor(bytes.Repeat([]byte(" "), 13))
	cipher = cipher[:len(cipher)-16]

	input := bytes.Repeat([]byte(" "), 10)
	input = append(input, []byte("admin")...)
	input = append(input, bytes.Repeat([]byte(" "), 11)...)

	cipher2 := profileFor(input)
	cipher2 = cipher2[16:]
	cipher2 = cipher2[:16]

	cipher = append(cipher, cipher2...)

	fmt.Println(string(decrypt(cipher)))
}

func CBCUser() (
	func(string) []byte,
	func([]byte) bool,
) {
	var (
		key  = generateAESKey()
		iv   = generateAESKey()
		prep = []byte("comment1=cooking%20MCs;userdata=")
		app  = []byte(";comment2=%20like%20a%20pound%20of%20bacon")
	)

	getUser := func(payload string) []byte {
		payload = strings.ReplaceAll(payload, ";", "\";\"")
		payload = strings.ReplaceAll(payload, "=", "\"=\"")

		msg := append(prep, append(padding([]byte(payload), 16), app...)...)

		cipher, err := CBCEncrypt(msg, iv, key)
		if err != nil {
			panic(err)
		}

		return cipher
	}

	isAdmin := func(data []byte) bool {
		decrypted := CBCDecrypt(data, iv, key)

		if strings.Contains(string(decrypted), ";admin=true;") {
			return true
		}

		return false
	}

	return getUser, isAdmin
}

func CBCBitsFlipping() {
	getUser, isAdmin := CBCUser()

	adminMsg := "AadminEtrueA"
	payload := getUser(adminMsg)

loop:
	for i := 0; i < 255; i++ {
		payload[16] = byte(i)

		for j := 0; j < 255; j++ {
			payload[16+6] = byte(j)

			for k := 0; k < 255; k++ {
				payload[16+len(adminMsg)-1] = byte(k)
				if isAdmin(payload) {
					fmt.Println("we are admins!")
					break loop
				}
			}
		}
	}
}

func validatePadding(s []byte) ([]byte, error) {
	if len(s) != 16 {
		panic("block length must be 16")
	}

	var padStart int
	for i, b := range s {
		if b == 4 && padStart == 0 {
			padStart = i
		}

		if b >= 0 && b <= 31 && b != 4 {
			return nil, errors.New("validation failed")
		}
	}

	return s[:padStart], nil
}

func init() {
	mathrand.Seed(time.Now().UnixNano())
}
