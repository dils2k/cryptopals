package cryptopals

import (
	"crypto/aes"
	"errors"
	"math/rand"
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
	for i := 0; i < 16; i++ {
		res[i] = byte(rand.Intn(256))
	}
	return res
}

func ECBORCBCEncrypt(msg []byte) []byte {
	key := generateAESKey()

	randappendNum := rand.Intn(5) + 5
	randappend := make([]byte, randappendNum)
	for i := 0; i < randappendNum; i++ {
		randappend[i] = byte(rand.Intn(256))
	}

	msg = append(randappend, append(msg, randappend...)...)

	var encrypted []byte

	if rand.Intn(2) == 0 {
		encrypted = ECBEncrypt(msg, key)
	} else {
		encrypted, _ = CBCEncrypt(msg, []byte{0}, key)
	}

	return encrypted
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
