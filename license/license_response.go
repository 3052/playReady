package license

import (
   "bytes"
   "crypto/aes"
   "encoding/base64"
   "encoding/binary"
   "errors"
   "github.com/deatil/go-cryptobin/mac"
)

func (l *LicenseResponse) Verify(content_integrity []byte) error {
   data := l.Encode()
   data = data[:len(l.RawData)-int(l.SignatureObject.Length)]
   block, err := aes.NewCipher(content_integrity)
   if err != nil {
      return err
   }
   sum := mac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(sum, l.SignatureObject.Data) {
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
         l.SignatureObject = new(Signature)
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

type XmrType uint16

const (
   OUTER_CONTAINER_ENTRY_TYPE                   XmrType = 1
   GLOBAL_POLICY_CONTAINER_ENTRY_TYPE           XmrType = 2
   PLAYBACK_POLICY_CONTAINER_ENTRY_TYPE         XmrType = 4
   MINIMUM_OUTPUT_PROTECTION_LEVELS_ENTRY_TYPE  XmrType = 5
   EXPLICIT_ANALOG_VIDEO_PROTECTION_ENTRY_TYPE  XmrType = 7
   ANALOG_VIDEO_OPL_ENTRY_TYPE                  XmrType = 8
   KEY_MATERIAL_CONTAINER_ENTRY_TYPE            XmrType = 9
   CONTENT_KEY_ENTRY_TYPE                       XmrType = 10
   SIGNATURE_ENTRY_TYPE                         XmrType = 11
   SERIAL_NUMBER_ENTRY_TYPE                     XmrType = 12
   RIGHTS_ENTRY_TYPE                            XmrType = 13
   EXPIRATION_ENTRY_TYPE                        XmrType = 18
   ISSUEDATE_ENTRY_TYPE                         XmrType = 19
   METERING_ENTRY_TYPE                          XmrType = 22
   GRACEPERIOD_ENTRY_TYPE                       XmrType = 26
   SOURCEID_ENTRY_TYPE                          XmrType = 34
   RESTRICTED_SOURCEID_ENTRY_TYPE               XmrType = 40
   DOMAIN_ID_ENTRY_TYPE                         XmrType = 41
   DEVICE_KEY_ENTRY_TYPE                        XmrType = 42
   POLICY_METADATA_ENTRY_TYPE                   XmrType = 44
   OPTIMIZED_CONTENT_KEY_ENTRY_TYPE             XmrType = 45
   EXPLICIT_DIGITAL_AUDIO_PROTECTION_ENTRY_TYPE XmrType = 46
   EXPIRE_AFTER_FIRST_USE_ENTRY_TYPE            XmrType = 48
   DIGITAL_AUDIO_OPL_ENTRY_TYPE                 XmrType = 49
   REVOCATION_INFO_VERSION_ENTRY_TYPE           XmrType = 50
   EMBEDDING_BEHAVIOR_ENTRY_TYPE                XmrType = 51
   SECURITY_LEVEL_ENTRY_TYPE                    XmrType = 52
   MOVE_ENABLER_ENTRY_TYPE                      XmrType = 55
   UPLINK_KID_ENTRY_TYPE                        XmrType = 59
   COPY_POLICIES_CONTAINER_ENTRY_TYPE           XmrType = 60
   COPY_COUNT_ENTRY_TYPE                        XmrType = 61
   REMOVAL_DATE_ENTRY_TYPE                      XmrType = 80
   AUX_KEY_ENTRY_TYPE                           XmrType = 81
   UPLINKX_ENTRY_TYPE                           XmrType = 82
   REAL_TIME_EXPIRATION_ENTRY_TYPE              XmrType = 85
   EXPLICIT_DIGITAL_VIDEO_PROTECTION_ENTRY_TYPE XmrType = 88
   DIGITAL_VIDEO_OPL_ENTRY_TYPE                 XmrType = 89
   SECURESTOP_ENTRY_TYPE                        XmrType = 90
   COPY_UNKNOWN_OBJECT_ENTRY_TYPE               XmrType = 65533
   GLOBAL_POLICY_UNKNOWN_OBJECT_ENTRY_TYPE      XmrType = 65533
   PLAYBACK_UNKNOWN_OBJECT_ENTRY_TYPE           XmrType = 65533
   COPY_UNKNOWN_CONTAINER_ENTRY_TYPE            XmrType = 65534
   UNKNOWN_CONTAINERS_ENTRY_TYPE                XmrType = 65534
   PLAYBACK_UNKNOWN_CONTAINER_ENTRY_TYPE        XmrType = 65534
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
   SignatureObject  *Signature
   AuxKeyObject     *AuxKeys
}
