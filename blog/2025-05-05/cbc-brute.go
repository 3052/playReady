package main

import (
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "fmt"
   "os"
   
   "slices"
)

const stage1 = "INNER_MSTAR_FILE"

func main() {
   src, err := os.ReadFile("zgpriv_protected.dat.mb180")
   if err != nil {
      panic(err)
   }
   key, err := os.ReadFile("mboot_emmc_mb180.bin")
   if err != nil {
      panic(err)
   }
   slices.Reverse(key)
   var iv [16]byte
   dst := make([]byte, len(src))
   for len(key) >= 16 {
      block, err := aes.NewCipher(key[:16])
      if err != nil {
         panic(err)
      }
      cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(dst, src)
      if bytes.Contains(dst, []byte(stage1)) {
         fmt.Println("pass")
         return
      }
      key = key[1:]
   }
   fmt.Println("fail")
}
