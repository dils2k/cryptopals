package cryptopals

import (
	"crypto/aes"
	"errors"
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
		if i == len(blocks)-1 {
			b = padding(b, 16)
		}
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
			b = RepeatingKeyXOR(b, resBlocks[i-1])
		}
		resBlocks = append(resBlocks, b)
	}

	var res []byte
	for _, b := range resBlocks {
		res = append(res, b...)
	}

	return res
}

func ECBEncrypt(msg, key []byte) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	encrypted := make([]byte, len(msg))

	size := cipher.BlockSize()

	for bs, be := 0, size; bs < len(msg); bs, be = bs+size, be+size {
		cipher.Encrypt(encrypted[bs:be], msg[bs:be])
	}

	return encrypted
}
