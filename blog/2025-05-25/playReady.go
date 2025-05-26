package main

import (
   "fmt"
   "tanith.dev/goplayready/certificate"
)

func main() {
   var chain certificate.Chain
   err := chain.LoadFile("../../secrets/g1")
   if err != nil {
      panic(err)
   }
   manufacturer := chain.Certs[0].ManufacturerInfo
   manufacturer_name := manufacturer.ManufacturerName.Value
   model_name := manufacturer.ModelName.Value
   model_number := manufacturer.ModelNumber.Value
   security_level := chain.Certs[0].CertificateInfo.SecurityLevel
   fmt.Printf("%+v\n", security_level)
   fmt.Printf("%q\n", manufacturer_name)
   fmt.Printf("%q\n", model_name)
   fmt.Printf("%q\n", model_number)
}
