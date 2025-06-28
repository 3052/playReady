package elliptic

import (
   "encoding/hex"
   "fmt"
   "testing"
)

const wmrmPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

func Test(t *testing.T) {
   data, err := hex.DecodeString(wmrmPublicKey)
   if err != nil {
      t.Fatal(err)
   }
   x, y := func0(data)
   fmt.Print(x, "\n", y, "\n")
}
