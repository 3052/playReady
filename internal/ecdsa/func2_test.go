package ecdsa

import (
   "fmt"
   "testing"
)

func Test2(t *testing.T) {
   data, err := func2()
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%x\n", data)
}
