package main

import (
   "41.neocities.org/playReady"
   "bytes"
   "encoding/hex"
   "errors"
   "io"
   "log"
   "net/http"
   "os"
)

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}

var SL2000 = struct {
   dir string
   g1  string
   z1  string
}{
   dir: "../ignore/",
   g1:  "g1",
   z1:  "z1",
}

func main() {
   err := do_leaf()
   if err != nil {
      panic(err)
   }
   err = do_key()
   if err != nil {
      panic(err)
   }
}

var microsoft = struct {
   key    string
   kid_wv string
   url    string
}{
   key:    "00000000000000000000000000000000",
   kid_wv: "10000000000000000000000000000000",
   url:    "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=ck:AAAAAAAAAAAAAAAAAAAAAA==,ckt:aescbc",
}

func do_key() error {
   data, err := os.ReadFile(SL2000.dir + "certificate")
   if err != nil {
      return err
   }
   var certificate playReady.Chain
   err = certificate.Decode(data)
   if err != nil {
      return err
   }
   data, err = os.ReadFile(SL2000.dir + "signEncryptKey")
   if err != nil {
      return err
   }
   var signEncryptKey playReady.EcKey
   signEncryptKey.Decode(data)
   kid, err := hex.DecodeString(microsoft.kid_wv)
   if err != nil {
      return err
   }
   playReady.UuidOrGuid(kid)
   data, err = certificate.RequestBody(signEncryptKey, kid)
   if err != nil {
      return err
   }
   resp, err := http.Post(microsoft.url, "text/xml", bytes.NewReader(data))
   if err != nil {
      return err
   }
   defer resp.Body.Close()
   data, err = io.ReadAll(resp.Body)
   if err != nil {
      return err
   }
   if resp.StatusCode != http.StatusOK {
      return errors.New(string(data))
   }
   var license playReady.License
   err = license.Decrypt(signEncryptKey, data)
   if err != nil {
      return err
   }
   content := license.ContentKey
   playReady.UuidOrGuid(content.KeyID[:])
   if hex.EncodeToString(content.KeyID[:]) != microsoft.kid_wv {
      return errors.New(".KeyID")
   }
   if hex.EncodeToString(content.Key[:]) != microsoft.key {
      return errors.New(".Key")
   }
   return nil
}

func do_leaf() error {
   data, err := os.ReadFile(SL2000.dir + SL2000.g1)
   if err != nil {
      return err
   }
   var certificate playReady.Chain
   err = certificate.Decode(data)
   if err != nil {
      return err
   }
   data, err = os.ReadFile(SL2000.dir + SL2000.z1)
   if err != nil {
      return err
   }
   var z1 playReady.EcKey
   z1.Decode(data)
   signEncryptKey, err := playReady.Fill('s').Key()
   if err != nil {
      return err
   }
   err = certificate.Leaf(&z1, signEncryptKey)
   if err != nil {
      return err
   }
   err = write_file(SL2000.dir+"certificate", certificate.Encode())
   if err != nil {
      return err
   }
   return write_file(SL2000.dir+"signEncryptKey", signEncryptKey.Private())
}
