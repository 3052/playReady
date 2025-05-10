package main

import "fmt"

func main() {
   dev_id := [16]uint8{0x38, 0x00, 0x38, 0x02, 0x38, 0x04}
   fmt.Printf("%X\n", dev_id)
}
