package cryptopals

func PKCSPadding(msg []byte, blen int) []byte {
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
