package ecdsa

import (
   "encoding/hex"
   "fmt"
   "testing"
)

func Test1(t *testing.T) {
   _, err := func1()
   if err != nil {
      t.Fatal(err)
   }
}

func Test0(t *testing.T) {
   data, err := hex.DecodeString(wmrmPublicKey)
   if err != nil {
      t.Fatal(err)
   }
   x, y := func0(data)
   fmt.Print(x, "\n", y, "\n")
}

const wmrmPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"
