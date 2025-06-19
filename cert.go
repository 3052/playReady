package playReady

import (
   "encoding/binary"
   "errors"
)

func (c *Certificate) decode(data []byte) (int, error) {
   n := copy(c.Magic[:], data)
   if string(c.Magic[:]) != "CERT" {
      return 0, errors.New("failed to find cert magic")
   }
   c.Version = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.LengthToSignature = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.rawData = data[n:][:c.Length-16]
   n += len(c.rawData)
   var n1 int
   for n1 < len(c.rawData) {
      var value ftlv
      n1 += value.decode(c.rawData[n1:])
      switch value.Type {
      case objTypeBasic: // 1
         c.certificateInfo = &certificateInfo{}
         c.certificateInfo.decode(value.Value)
      case objTypeDevice: // 4
      case objTypeFeature: // 5
         c.features = &features{}
         c.features.decode(value.Value)
      case objTypeKey: // 6
         c.keyInfo = &keyInfo{}
         c.keyInfo.decode(value.Value)
      case objTypeManufacturer: // 7
         c.manufacturerInfo = &manufacturer{}
         c.manufacturerInfo.decode(value.Value)
      case objTypeSignature: // 8
         c.signature = &certificateSignature{}
         c.signature.decode(value.Value)
      default:
         return 0, errors.New("FTLV.decode")
      }
   }
   return n, nil
}

type Certificate struct {
   Magic             [4]byte
   Version           uint32
   Length            uint32
   LengthToSignature uint32
   rawData           []byte
   certificateInfo   *certificateInfo
   features          *features
   keyInfo           *keyInfo
   manufacturerInfo  *manufacturer
   signature         *certificateSignature
}

// encode encodes the Cert structure into a byte slice.
func (c *Certificate) encode() []byte {
   data := c.Magic[:]
   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.LengthToSignature)
   return append(data, c.rawData...)
}
