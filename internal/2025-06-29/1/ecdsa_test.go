package ecdsa

import (
   "fmt"
   "testing"
)

func Test(t *testing.T) {
   r, s, x, y := sign()
   fmt.Println(verify(r, s, x, y))
}
