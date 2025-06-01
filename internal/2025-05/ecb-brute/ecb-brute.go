package main

import (
   "bytes"
   "crypto/aes"
   "fmt"
   "iter"
   "log"
   "os"
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

const (
   stage0 = "MSTAR_SECURE_STORE_FILE_MAGIC_ID"
   stage1 = "INNER_MSTAR_FILE"
)

func get_source(data []byte) iter.Seq[[]byte] {
   magic_id := bytes.Index(data, []byte(stage0))
   return func(yield func([]byte) bool) {
      for i := 0; i < magic_id; i++ {
         if len(data[i:]) % 16 == 0 {
            log.Println("source", i)
            if !yield(data[i:]) {
               return
            }
         }
      }
   }
}

func get_key(data []byte) iter.Seq[[]byte] {
   return func(yield func([]byte) bool) {
      for len(data) >= 16 {
         if !yield(data[:16]) {
            return
         }
         data = data[1:]
      }
   }
}

func main() {
   sources, err := os.ReadFile("zgpriv_protected.dat")
   if err != nil {
      panic(err)
   }
   keys, err := os.ReadFile("MBOOT.bin")
   if err != nil {
      panic(err)
   }
   for source := range get_source(sources) {
      for key := range get_key(keys) {
         dest := DecryptAes128Ecb(source, key)
         if bytes.Contains(dest, []byte(stage1)) {
            fmt.Println("pass")
            return
         }
      }
   }
   fmt.Println("fail")
}
