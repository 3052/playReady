package playReady

import (
   "41.neocities.org/playReady/license"
   "bytes"
   "crypto/aes"
   "encoding/base64"
   "encoding/binary"
   "errors"
   "github.com/deatil/go-cryptobin/mac"
)

type LicenseResponse struct {
   RawData          []byte
   Magic            [4]byte
   Offset           uint16
   Version          uint16
   RightsId         [16]byte
   OuterContainer   FTLV
   ContentKeyObject *ContentKey
   ECCKeyObject     *ECCKey
   SignatureObject  *license.Signature
   AuxKeyObject     *AuxKeys
}

func (l *LicenseResponse) Verify(content_integrity []byte) error {
   data := l.Encode()
   data = data[:len(l.RawData)-int(l.SignatureObject.Length)]
   block, err := aes.NewCipher(content_integrity)
   if err != nil {
      return err
   }
   data = mac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.SignatureObject.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

func (l *LicenseResponse) Decode(data []byte) error {
   l.RawData = make([]byte, len(data))
   copy(l.RawData, data)

   n := copy(l.Magic[:], data)
   l.Offset = binary.BigEndian.Uint16(data[n:])
   n += 2
   l.Version = binary.BigEndian.Uint16(data[n:])
   n += 2
   n += copy(l.RightsId[:], data[n:])

   j, err := l.OuterContainer.Decode(data[n:])

   if err != nil {
      return err
   }
   n += int(j)

   var size uint32

   for size < l.OuterContainer.Length-16 {
      var ftlv FTLV
      i, err := ftlv.Decode(l.OuterContainer.Value[int(size):])
      if err != nil {
         return err
      }
      switch XmrType(ftlv.Type) {
      case GLOBAL_POLICY_CONTAINER_ENTRY_TYPE: // 2
         // Rakuten
      case PLAYBACK_POLICY_CONTAINER_ENTRY_TYPE: // 4
         // Rakuten
      case KEY_MATERIAL_CONTAINER_ENTRY_TYPE: // 9
         var j uint32
         for j < ftlv.Length-16 {
            var ftlv2 FTLV
            k, err := ftlv2.Decode(ftlv.Value[j:])
            if err != nil {
               return err
            }
            switch XmrType(ftlv2.Type) {
            case CONTENT_KEY_ENTRY_TYPE: // 10
               l.ContentKeyObject = new(ContentKey)
               err = l.ContentKeyObject.Decode(ftlv2.Value)
               if err != nil {
                  return err
               }
            case DEVICE_KEY_ENTRY_TYPE: // 42
               l.ECCKeyObject = new(ECCKey)
               err = l.ECCKeyObject.Decode(ftlv2.Value)
               if err != nil {
                  return err
               }
            case AUX_KEY_ENTRY_TYPE: // 81
               l.AuxKeyObject = new(AuxKeys)
               err = l.AuxKeyObject.Decode(ftlv2.Value)
               if err != nil {
                  return err
               }
            default:
               return errors.New("ftlv2.Type")
            }
            j += k
         }
      case SIGNATURE_ENTRY_TYPE: // 11
         l.SignatureObject = new(license.Signature)
         err := l.SignatureObject.Decode(ftlv.Value)
         l.SignatureObject.Length = uint16(ftlv.Length)
         if err != nil {
            return err
         }
      default:
         return errors.New("ftlv.Type")
      }
      size += i
   }

   return nil
}

func (l *LicenseResponse) Encode() []byte {
   data := l.Magic[:]
   data = binary.BigEndian.AppendUint16(data, l.Offset)
   data = binary.BigEndian.AppendUint16(data, l.Version)
   data = append(data, l.RightsId[:]...)

   data = append(data, l.OuterContainer.Encode()...)
   return data
}

func (l *LicenseResponse) Parse(data string) error {
   decoded, err := base64.StdEncoding.DecodeString(data)

   if err != nil {
      return err
   }
   return l.Decode(decoded)
}
