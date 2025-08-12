package main

import (
   "crypto/aes"
   "crypto/cipher"
   "flag"
   "os"
)

func decrypt(in, out string) error {
   data, err := os.ReadFile(in)
   if err != nil {
      return err
   }
   key, err := os.ReadFile("key.bin")
   if err != nil {
      return err
   }
   block, err := aes.NewCipher(key)
   if err != nil {
      return err
   }
   var iv [16]byte
   cipher.NewCTR(block, iv[:]).XORKeyStream(data, data)
   return os.WriteFile(out, data, os.ModePerm)
}

func ok(in, out string) bool {
   if in != "" {
      if out != "" {
         return true
      }
   }
   return false
}

func main() {
   in := flag.String("i", "", "in")
   out := flag.String("o", "", "out")
   flag.Parse()
   if ok(*in, *out) {
      err := decrypt(*in, *out)
      if err != nil {
         panic(err)
      }
   } else {
      flag.Usage()
   }
}
