package main

import (
   "bytes"
   "crypto/aes"
   "fmt"
   "os"
)

const (
   stage0 = "MSTAR_SECURE_STORE_FILE_MAGIC_ID"
   stage1 = "INNER_MSTAR_FILE"
)

func DecryptAes128Ecb(data, key []byte) []byte {
    cipher, _ := aes.NewCipher([]byte(key))
    decrypted := make([]byte, len(data))
    size := 16
    for lo, hi := 0, size; lo < len(data); lo, hi = lo+size, hi+size {
      cipher.Decrypt(decrypted[lo:hi], data[lo:hi])
    }
    return decrypted
}

func main() {
   data, err := os.ReadFile("zgpriv_protected.dat")
   if err != nil {
      panic(err)
   }
   key, err := os.ReadFile("MBOOT.bin")
   if err != nil {
      panic(err)
   }
   for len(key) >= 16 {
      data = DecryptAes128Ecb(data, key[:16])
      if bytes.Contains(data, []byte(stage1)) {
         fmt.Println("pass")
         break
      }
      key = key[1:]
   }
}
