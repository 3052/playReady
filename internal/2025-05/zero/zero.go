package main

import (
   "crypto/aes"
   "fmt"
   "github.com/andreburgaud/crypt2go/ecb"
   "slices"
)

const (
   stage0 = "MSTAR_SECURE_STORE_FILE_MAGIC_ID"
   stage1 = "INNER_MSTAR_FILE"
)

var puCommonTaString = []byte{'M', 'S', 't', 'a', 'r', 'C',
   'o', 'm', 'm', 'o', 'n', 'T', 'A', 'K', 'e', 'y'}

var hwKey = []byte{0xE0, 0x10, 0x01, 0xFF, 0x0F, 0xAA, 0x55, 0xFC,
   0x92, 0x4D, 0x53, 0x54, 0x41, 0xFF, 0x07, 0x00}

func main() {
   block, err := aes.NewCipher(hwKey)
   if err != nil {
      panic(err)
   }
   mode := ecb.NewECBEncrypter(block)
   ciphertext := make([]byte, len(puCommonTaString))
   mode.CryptBlocks(ciphertext, puCommonTaString)
   fmt.Printf("%X\n", ciphertext)
   slices.Reverse(ciphertext)
   fmt.Printf("%X\n", ciphertext)
   // 8E560AE3BF40A069B95B34E4C42844DB
   // DB4428C4E4345BB969A040BFE30A568E
}
