package main

import (
   "crypto/aes"
   "crypto/cipher"
   "os"
   "encoding/hex"
)

const (
   stage0 = "MSTAR_SECURE_STORE_FILE_MAGIC_ID"
   stage1 = "INNER_MSTAR_FILE"
)

func main() {
   key, err := os.ReadFile("AESboot.bin")
   if err != nil {
      panic(err)
   }
   key, err = hex.DecodeString("BC1197CA30AA0FC84F7FE62E09FD3D9F")
   if err != nil {
      panic(err)
   }
   block, err := aes.NewCipher(key)
   if err != nil {
      panic(err)
   }
   var iv [16]byte
   data, err := os.ReadFile("zgpriv_protected.dat")
   if err != nil {
      panic(err)
   }
   cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(data, data)
   err = os.WriteFile("stage-1.dat", data, os.ModePerm)
   if err != nil {
      panic(err)
   }
}
