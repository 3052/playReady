package main

import (
   "crypto/aes"
   "crypto/cipher"
   "os"
)

func main() {
   key, err := os.ReadFile("AESboot.bin")
   if err != nil {
      panic(err)
   }
   block, err := aes.NewCipher(key)
   if err != nil {
      panic(err)
   }
   data, err := os.ReadFile("zgpriv_protected.dat")
   if err != nil {
      panic(err)
   }
   cipher.NewCBCDecrypter(block, key).CryptBlocks(data, data)
   err = os.WriteFile("stage-1.dat", data, os.ModePerm)
   if err != nil {
      panic(err)
   }
}
