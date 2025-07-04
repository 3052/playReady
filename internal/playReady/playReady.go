package main

import (
   "41.neocities.org/playReady"
   "encoding/base64"
   "flag"
   "fmt"
)

func do_guid(guid string) error {
   data, err := base64.StdEncoding.DecodeString(guid)
   if err != nil {
      return err
   }
   fmt.Printf("GUID %x\n", data)
   playReady.UuidOrGuid(data)
   fmt.Printf("UUID %x\n", data)
   return nil
}

func do_uuid(uuid string) error {
   data, err := base64.StdEncoding.DecodeString(uuid)
   if err != nil {
      return err
   }
   fmt.Printf("UUID %x\n", data)
   playReady.UuidOrGuid(data)
   fmt.Printf("GUID %x\n", data)
   return nil
}

func main() {
   uuid := flag.String("u", "", "UUID")
   guid := flag.String("g", "", "GUID")
   flag.Parse()
   var err error
   switch {
   case *guid != "":
      err = do_guid(*guid)
   case *uuid != "":
      err = do_uuid(*uuid)
   default:
      flag.Usage()
   }
   if err != nil {
      panic(err)
   }
}
