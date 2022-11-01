package cryptopals

import (
	"crypto/aes"
	"encoding/base64"
	"log"
	"math"
	"os"
)

func Hex2B64(s []byte) []byte {
	b64str := make([]byte, base64.RawStdEncoding.EncodedLen(len(s)))
	base64.RawStdEncoding.Encode(b64str, s)
	return b64str
}

func FixedXOR(s, key []byte) []byte {
	res := make([]byte, len(s))
	for i := range s {
		res[i] = s[i] ^ key[i]
	}
	return res
}

func SingleByteXOR(msg []byte) ([]byte, byte) {
	var (
		distance     float64
		decryptedMsg []byte
		key          byte
	)

	for i := 0; i < 255; i++ {
		var res []byte
		for _, c := range msg {
			res = append(res, c^byte(i))
		}

		gcharfreq := computeCharFreqForString(string(res))
		newDistance := charDistance(gcharfreq)

		if newDistance < distance || distance == 0 {
			distance = newDistance
			decryptedMsg = res
			key = byte(i)
		}
	}

	return decryptedMsg, key
}

func DetectSingleByteXOR(lines [][]byte) byte {
	var (
		distance float64
		key      byte
	)

	for _, l := range lines {
		for i := 0; i < 255; i++ {
			var res []byte
			for _, c := range l {
				res = append(res, c^byte(i))
			}

			gcharfreq := computeCharFreqForString(string(res))
			newDistance := charDistance(gcharfreq)

			if newDistance < distance || distance == 0 {
				distance = newDistance
				key = byte(i)
			}
		}
	}

	return key
}

func RepeatingKeyXOR(msg, key []byte) []byte {
	res := make([]byte, 0)

	ki := 0
	for i, c := range msg {
		if i%len(key) == 0 && i != 0 {
			ki = 0
		}
		res = append(res, c^key[ki])
		ki++
	}

	return res
}

func BreakRepeatingXOR(s []byte) []byte {
	var (
		klength  int
		distance float64
	)

	for i := 2; i <= 40; i++ {
		var sum float64
		for j := 0; j <= i*8; j += i {
			sum += float64(hammingDistance(s[j:j+i], s[j+i:j+2*i])) / float64(i)
		}

		if newDistance := sum / 8; newDistance < distance || distance == 0 {
			klength = i
			distance = newDistance
		}
	}

	chunks := chunkBy(s, klength)
	transposed := make([][]byte, klength)
	for i := range chunks {
		for j := range chunks[i] {
			transposed[j] = append(transposed[j], chunks[i][j])
		}
	}

	var key []byte
	for _, t := range transposed {
		_, k := SingleByteXOR(t)
		key = append(key, k)
	}

	return key
}

func ECBDecrypt(msg, key []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	decrypted := make([]byte, len(msg))

	size := cipher.BlockSize()

	for bs, be := 0, size; bs < len(msg); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], msg[bs:be])
	}

	return decrypted
}

func DetectECB(lines [][]byte) []byte {
	for _, l := range lines {
		blocks := chunkBy(l, 16)
		for i, b := range blocks {
			for _, ob := range blocks[i+1:] {
				equal := true
				for j := range b {
					if b[j] != ob[j] {
						equal = false
						break
					}
				}
				if equal {
					return l
				}
			}
		}
	}

	return nil
}

func chunkBy[T any](items []T, chunkSize int) (chunks [][]T) {
	for chunkSize < len(items) {
		items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
	}
	return append(chunks, items)
}

func hammingDistance(a, b []byte) int {
	abits := bytesToBits(a)
	bbits := bytesToBits(b)

	var distance int
	for i := range abits {
		if abits[i] != bbits[i] {
			distance++
		}
	}

	return distance
}

func bytesToBits(bs []byte) []int {
	var bits []int

	for _, b := range bs {
		for i := 0; i < 8; i++ {
			if b&1 == 1 {
				bits = append([]int{1}, bits...)
			} else {
				bits = append([]int{0}, bits...)
			}

			b = b >> 1
		}
	}

	return bits
}

var charFreq = func() map[rune]float64 {
	dat, err := os.ReadFile("./book.txt")
	if err != nil {
		log.Fatal("can't open a file", err)
	}

	return computeCharFreqForString(string(dat))
}()

func charDistance(g map[rune]float64) float64 {
	var sum float64
	for k := range charFreq {
		sum += math.Pow(g[k]-charFreq[k], 2)
	}

	return math.Sqrt(sum)
}

func computeCharFreqForString(s string) map[rune]float64 {
	charsAmount := make(map[rune]int)
	for _, c := range s {
		charsAmount[c]++
	}

	charsFreq := make(map[rune]float64)
	for k, v := range charsAmount {
		charsFreq[k] = float64(v) / float64(len(s)) * 100
	}

	return charsFreq
}
