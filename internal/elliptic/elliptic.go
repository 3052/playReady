package elliptic

import "math/big"

func func0(data []byte) (*big.Int, *big.Int) {
   x := new(big.Int).SetBytes(data[:32])
   y := new(big.Int).SetBytes(data[32:])
   return x, y
}
