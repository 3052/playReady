package main

import (
   "encoding/json"
   "os"
   "tanith.dev/goplayready/certificate"
)

func main() {
   var chain certificate.Chain
   err := chain.LoadFile("../../secrets/g1")
   if err != nil {
      panic(err)
   }
   file, err := os.Create(".json")
   if err != nil {
      panic(err)
   }
   defer file.Close()
   encode := json.NewEncoder(file)
   encode.SetIndent("", " ")
   err = encode.Encode(chain)
   if err != nil {
      panic(err)
   }
}
