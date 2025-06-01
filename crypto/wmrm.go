package crypto

import (
   "encoding/hex"
   "fmt"
   "math/big"
)

type WMRM struct{}

var WMRMPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

func (WMRM) Points() (*big.Int, *big.Int, error) {
   bytes, err := hex.DecodeString(WMRMPublicKey)

   if err != nil {
      fmt.Println("Error decoding hex string:", err)
   }

   x := new(big.Int).SetBytes(bytes[:32])
   y := new(big.Int).SetBytes(bytes[32:])

   return x, y, nil
}
