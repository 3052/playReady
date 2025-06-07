package playReady

import (
   "41.neocities.org/playReady/license"
   "encoding/binary"
   "errors"
   "github.com/beevik/etree"
)

type PlayReadyObject struct {
   Type   uint16
   Length uint16
   Data   string
}

type PlayReadyRecord struct {
   Length uint32
   Count  uint16
   Data   []byte
}

type ProtectionSystemHeaderBox struct {
   Size       uint32
   Type       [4]byte
   Version    uint8
   Flags      [3]byte
   SystemId   license.Guid
   KeyIdCount uint32
   KeyIds     []license.Guid
   Length     uint32
   Data       []byte
}

type Header struct {
   PSSHBox   *ProtectionSystemHeaderBox
   Record    *PlayReadyRecord
   Object    *PlayReadyObject
   WrmHeader *WrmHeader
}

type WrmHeader struct {
   Version string
   KeyIds  []license.Guid
   Data    *etree.Element
}

///

func (p *PlayReadyRecord) Decode(data []byte) bool {
   p.Length = binary.LittleEndian.Uint32(data)
   if int(p.Length) > len(data) {
      return false
   }
   data = data[4:]
   p.Count = binary.LittleEndian.Uint16(data)
   data = data[2:]
   p.Data = data
   return true
}

func (h *Header) ParseWrm(Wrm string) error {
   var head WrmHeader
   err := head.Decode(Wrm)
   if err != nil {
      return err
   }
   h.WrmHeader = &head
   return nil
}

func (w *WrmHeader) Decode(Wrm string) error {
   ParsedWrm := etree.NewDocument()
   if err := ParsedWrm.ReadFromString(Wrm); err != nil {
      return err
   }

   version := ParsedWrm.Root().SelectAttrValue("version", "")

   if version == "" {
      return errors.New("invalid wrm header")
   }

   w.Version = version

   var KeyIds []*etree.Element

   switch version {
   case "4.0.0.0":
      KeyIds = ParsedWrm.FindElements("/WRMHEADER/DATA/KID")
   case "4.1.0.0":
      KeyIds = ParsedWrm.FindElements("/WRMHEADER/DATA/PROTECTINFO/KID")
   case "4.2.0.0":
   case "4.3.0.0":
      KeyIds = ParsedWrm.FindElements("/WRMHEADER/DATA/PROTECTINFO/KIDS/*")
   }

   w.KeyIds = make([]license.Guid, len(KeyIds))

   for i, e := range KeyIds {
      var KeyId license.Guid

      if e.Text() != "" {
         err := KeyId.Base64Decode(e.Text())
         if err != nil {
            return err
         }
      } else {
         err := KeyId.Base64Decode(e.SelectAttrValue("VALUE", ""))
         if err != nil {
            return err
         }
      }

      w.KeyIds[i] = KeyId
   }

   w.Data = ParsedWrm.Root()

   return nil
}
