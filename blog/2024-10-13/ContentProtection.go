package main

import (
   "bytes"
   "encoding/base64"
   "encoding/xml"
   "fmt"
)

type chardata []byte

func (d *chardata) UnmarshalText(text []byte) error {
   var err error
   *d, err = base64.StdEncoding.AppendDecode(nil, text)
   if err != nil {
      return err
   }
   *d = bytes.ReplaceAll(*d, []byte{0}, nil)
   return nil
}

func main() {
   var protect struct {
      Pssh        chardata   `xml:"pssh"`
      Pro         struct {
         Text  chardata `xml:",chardata"`
      } `xml:"pro"`
   }
   err := xml.Unmarshal([]byte(data), &protect)
   if err != nil {
      panic(err)
   }
   fmt.Printf("%q\n", protect.Pssh)
   fmt.Printf("%q\n", protect.Pro.Text)
}

const data = `
<ContentProtection value="MSPR 2.0" schemeIdUri="urn:uuid:9a04f079-9840-4286-ab92-e65be0885f95">
   <cenc:pssh>AAAB5HBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAAcTEAQAAAQABALoBPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4AcwA9ACIAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANwAvADAAMwAvAFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA8AEQAQQBUAEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgBiAG4AaAB5AEMATwBmADUAWAAwAGEAagBvAGsANQBiAEQAdgBqADYAUgBRAD0APQA8AC8ASwBJAEQAPgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==</cenc:pssh>
   <pro xmlns="urn:microsoft:playready">xAEAAAEAAQC6ATwAVwBSAE0ASABFAEEARABFAFIAIAB4AG0AbABuAHMAPQAiAGgAdAB0AHAAOgAvAC8AcwBjAGgAZQBtAGEAcwAuAG0AaQBjAHIAbwBzAG8AZgB0AC4AYwBvAG0ALwBEAFIATQAvADIAMAAwADcALwAwADMALwBQAGwAYQB5AFIAZQBhAGQAeQBIAGUAYQBkAGUAcgAiACAAdgBlAHIAcwBpAG8AbgA9ACIANAAuADAALgAwAC4AMAAiAD4APABEAEEAVABBAD4APABQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsARQBZAEwARQBOAD4AMQA2ADwALwBLAEUAWQBMAEUATgA+ADwAQQBMAEcASQBEAD4AQQBFAFMAQwBUAFIAPAAvAEEATABHAEkARAA+ADwALwBQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsASQBEAD4AYgBuAGgAeQBDAE8AZgA1AFgAMABhAGoAbwBrADUAYgBEAHYAagA2AFIAUQA9AD0APAAvAEsASQBEAD4APAAvAEQAQQBUAEEAPgA8AC8AVwBSAE0ASABFAEEARABFAFIAPgA=</pro>
</ContentProtection>
`
