package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "crypto/aes"
   "encoding/binary"
   "errors"
   "github.com/deatil/go-cryptobin/mac"
)

func (f *field) size() int {
   n := 2 // Flag
   n += 2 // Type
   n += 4 // Length
   if f.field != nil {
      for _, field1 := range f.field {
         n += field1.size()
      }
   } else {
      n += len(f.Value)
   }
   return n
}

type field struct {
   Flag  uint16 // this can be 0 or 1
   Type  uint16
   Value []byte
   field []field
}

func (l *License) Encode() []byte {
   data := l.Magic[:]
   data = binary.BigEndian.AppendUint16(data, l.Offset)
   data = binary.BigEndian.AppendUint16(data, l.Version)
   data = append(data, l.RightsID[:]...)
   value := field{
      Type: 1,
      field: []field{
         { Type: 2 }, // global policy
         { Type: 4 }, // playback policy
         {
            Type: 9, // key material
            field: []field{
               {
                  Type: 10, // content key
                  Value: nil,
               },
               {
                  Type: 42, // ecc key
                  Value: nil,
               },
               {
                  Type: 81, // aux key
                  Value: nil,
               },
            },
         },
         {
            Type: 11, // signature
            Value: nil,
         },
      },
   }
   return value.Append(data)
}

func (f *field) Append(data []byte) []byte {
   data = binary.BigEndian.AppendUint16(data, f.Flag)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(
      data, uint32(f.size()),
   )
   if f.field != nil {
      for _, field1 := range f.field {
         data = field1.Append(data)
      }
   } else {
      data = append(data, f.Value...)
   }
   return data
}

func (f *field) decode(data []byte) (int, error) {
   f.Flag = binary.BigEndian.Uint16(data)
   n := 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   length := binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:length]
   n += len(f.Value)
   return n, nil
}
func (l *licenseSignature) size() int {
   n := 2 // type
   n += 2 // length
   n += len(l.Data)
   return n
}

func (l *License) verify(data []byte) error {
   signature := new(field).size() + l.signature.size()
   data = data[:len(data)-signature]
   block, err := aes.NewCipher(l.ContentKey.Integrity[:])
   if err != nil {
      return err
   }
   data = mac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.signature.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

type licenseSignature struct {
   Type   uint16
   Length uint16
   Data   []byte
}

func (l *License) Decrypt(signEncrypt EcKey, data []byte) error {
   var envelope xml.EnvelopeResponse
   err := envelope.Unmarshal(data)
   if err != nil {
      return err
   }
   data = envelope.Body.AcquireLicenseResponse.AcquireLicenseResult.Response.LicenseResponse.Licenses.License
   err = l.decode(data)
   if err != nil {
      return err
   }
   if !bytes.Equal(l.eccKey.Value, signEncrypt.public()) {
      return errors.New("license response is not for this device")
   }
   err = l.ContentKey.decrypt(signEncrypt[0], l.auxKeys)
   if err != nil {
      return err
   }
   return l.verify(data)
}

func (l *License) decode(data []byte) error {
   n := copy(l.Magic[:], data)
   data = data[n:]
   l.Offset = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Version = binary.BigEndian.Uint16(data)
   data = data[2:]
   n = copy(l.RightsID[:], data)
   data = data[n:]
   var outer field
   _, err := outer.decode(data) // Type 1
   if err != nil {
      return err
   }
   for len(outer.Value) >= 1 {
      var inner field
      n, err = inner.decode(outer.Value)
      if err != nil {
         return err
      }
      outer.Value = outer.Value[n:]
      switch xmrType(inner.Type) {
      case globalPolicyContainerEntryType: // 2
         // Rakuten
      case playbackPolicyContainerEntryType: // 4
         // Rakuten
      case keyMaterialContainerEntryType: // 9
         for len(inner.Value) >= 1 {
            var key field
            n, err = key.decode(inner.Value)
            if err != nil {
               return err
            }
            inner.Value = inner.Value[n:]
            switch xmrType(key.Type) {
            case contentKeyEntryType: // 10
               l.ContentKey = &ContentKey{}
               l.ContentKey.decode(key.Value)
            case deviceKeyEntryType: // 42
               l.eccKey = &eccKey{}
               l.eccKey.decode(key.Value)
            case auxKeyEntryType: // 81
               l.auxKeys = &auxKeys{}
               l.auxKeys.decode(key.Value)
            default:
               return errors.New("field.type")
            }
         }
      case signatureEntryType: // 11
         l.signature = &licenseSignature{}
         l.signature.decode(inner.Value)
      default:
         return errors.New("field.type")
      }
   }
   return nil
}

func (l *licenseSignature) decode(data []byte) {
   l.Type = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Data = data
}

type License struct {
   Magic          [4]byte           // 0
   Offset         uint16            // 1
   Version        uint16            // 2
   RightsID       [16]byte          // 3
   GlobalPolicy   struct{}          // 4.2
   PlaybackPolicy struct{}          // 4.4
   ContentKey     *ContentKey       // 4.9.10
   eccKey         *eccKey           // 4.9.42
   auxKeys        *auxKeys          // 4.9.81
   signature      *licenseSignature // 4.11
}
