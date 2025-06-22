package playReady

import (
   "41.neocities.org/playReady/xml"
   "bytes"
   "encoding/binary"
   "errors"
)

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

func (l *License) Decrypt(signEncrypt EcKey, data []byte) error {
   var envelope xml.EnvelopeResponse
   err := envelope.Unmarshal(data)
   if err != nil {
      return err
   }
   err = l.decode(envelope.
      Body.
      AcquireLicenseResponse.
      AcquireLicenseResult.
      Response.
      LicenseResponse.
      Licenses.
      License,
   )
   if err != nil {
      return err
   }
   if !bytes.Equal(l.eccKey.Value, signEncrypt.public()) {
      return errors.New("license response is not for this device")
   }
   return l.ContentKey.decrypt(signEncrypt[0], l.auxKeys)
}
