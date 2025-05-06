package main

import (
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "fmt"
   "os"
)

const stage1 = "INNER_MSTAR_FILE"

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
      block, err := aes.NewCipher(key[:16])
      if err != nil {
         panic(err)
      }
      cipher.NewCBCDecrypter(block, key[:16]).CryptBlocks(data, data)
      if bytes.Contains(data, []byte(stage1)) {
         fmt.Println("pass")
         break
      }
      key = key[1:]
   }
}
