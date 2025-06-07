package challenge

import (
   "encoding/xml"
   "os"
   "testing"
)

func Test(t *testing.T) {
   var value Envelope
   value.New()
   encode := xml.NewEncoder(os.Stdout)
   encode.Indent("", " ")
   err := encode.Encode(value)
   if err != nil {
      t.Fatal(err)
   }
}
