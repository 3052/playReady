package playReady

import (
   "encoding/xml"
   "fmt"
   "os"
   "testing"
)

type envelope_value struct {
   XMLName xml.Name `xml:"soap:Envelope"`
   Body struct {
      AcquireLicense *struct{}
      AcquireLicenseResponse *struct{}
   } `xml:"soap:Body"`
}

const envelope_data = `<soap:Envelope>
 <soap:Body>
  <AcquireLicense></AcquireLicense>
 </soap:Body>
</soap:Envelope>`

func TestEnvelopeResponse(t *testing.T) {
   var value envelope_value
   err := xml.Unmarshal([]byte(envelope_data), &value)
   if err != nil {
      t.Fatal(err)
   }
   fmt.Printf("%+v\n", value)
}

func TestEnvelopeRequest(t *testing.T) {
   var value envelope_value
   value.Body.AcquireLicense = &struct{}{}
   encode := xml.NewEncoder(os.Stdout)
   encode.Indent("", " ")
   err := encode.Encode(value)
   if err != nil {
      t.Fatal(err)
   }
}
