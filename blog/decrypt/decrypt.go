package main

import (
   "crypto/aes"
   "os"
)

const (
   stage0 = "MSTAR_SECURE_STORE_FILE_MAGIC_ID"
   stage1 = "INNER_MSTAR_FILE"
)

// github.com/qdvbp/mstar-tools/blob/master/default_keys/AESboot.bin
func main() {
   key, err := os.ReadFile("AESboot.bin")
   if err != nil {
      panic(err)
   }
   data, err := os.ReadFile("zgpriv_protected.dat")
   if err != nil {
      panic(err)
   }
   data = DecryptAes128Ecb(data, key)
   os.WriteFile("stage-1.dat", data, os.ModePerm)
}

func DecryptAes128Ecb(data, key []byte) []byte {
    cipher, _ := aes.NewCipher([]byte(key))
    decrypted := make([]byte, len(data))
    size := 16
    for lo, hi := 0, size; lo < len(data); lo, hi = lo+size, hi+size {
      cipher.Decrypt(decrypted[lo:hi], data[lo:hi])
    }
    return decrypted
}
