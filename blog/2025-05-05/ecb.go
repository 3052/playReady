package main

import (
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "encoding/hex"
   "fmt"
   "os"
)

const (
   //stage0 = "MSTAR_SECURE_STORE_FILE_MAGIC_ID"
   stage1 = "INNER_MSTAR_FILE"
)

func main() {
   src, err := os.ReadFile("KeyBox.bin")
   if err != nil {
      panic(err)
   }
   src = src[20:]
   for _, raw_key := range keys {
      key, err := hex.DecodeString(raw_key)
      if err != nil {
         panic(err)
      }
      // ECB
      dst := DecryptAes128Ecb(src, key)
      if bytes.Contains(dst, []byte(stage1)) {
         fmt.Println("pass")
         break
      }
      // CBC zero
      block, err := aes.NewCipher(key)
      if err != nil {
         panic(err)
      }
      var iv [16]byte
      cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(dst, src)
      if bytes.Contains(dst, []byte(stage1)) {
         fmt.Println("pass")
         break
      }
      // CBC key
      cipher.NewCBCDecrypter(block, key).CryptBlocks(dst, src)
      if bytes.Contains(dst, []byte(stage1)) {
         fmt.Println("pass")
         break
      }
   }
   fmt.Println("fail")
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

// github.com/qdvbp/mstar-tools/blob/master/default_keys/AESboot.bin
var keys = []string{
   "0007FF4154534D92FC55AA0FFF0110E0", // default
   "24490B4CC95F739CE34138478E47139E", // advised by lossui (not sure when to be used)
   "BC1197CA30AA0FC84F7FE62E09FD3D9F", // Hisense
   "8981D083B3D53B3DF1AC529A70F244C0", // Vestel MB130
   "3503B1CDE3401EC06030C12A4311F4A5", // e.g. KTC
   "E33AB4C45C2570B8AD15A921F752DEB6", // LG
   "206955BFC5F0FAF84396C2379237AC08", // in many older dumps (not sure if usable)
   "B9C956919B48E1671564F4CADB5FE63C", // in some older dumps 
   "F8686BF589D42AE2ABD019775A541420", // AOC/TPV
}
