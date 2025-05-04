package main

import (
   "crypto/aes"
   "crypto/cipher"
   "os"
   //"encoding/hex"
)

func main() {
   key, err := os.ReadFile("AESboot.bin")
   if err != nil {
      panic(err)
   }
   //key, err = hex.DecodeString("BC1197CA30AA0FC84F7FE62E09FD3D9F")
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
