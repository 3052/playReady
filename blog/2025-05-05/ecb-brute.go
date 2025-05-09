package main

import (
   "bytes"
   "crypto/aes"
   "fmt"
   "os"
   //"slices"
)

const stage1 = "INNER_MSTAR_FILE"

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
   src, err := os.ReadFile("zgpriv_protected.dat.mb180")
   if err != nil {
      panic(err)
   }
   
   src = src[16:]
   
   key, err := os.ReadFile("mboot_emmc_mb180.bin")
   if err != nil {
      panic(err)
   }
   
   //slices.Reverse(key)
   
   for len(key) >= 16 {
      dst := DecryptAes128Ecb(src, key[:16])
      if bytes.Contains(dst, []byte(stage1)) {
         fmt.Println("pass")
         return
      }
      key = key[1:]
   }
   fmt.Println("fail")
}
