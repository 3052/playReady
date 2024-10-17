package playReady

type cert_attr struct {
   tag int
}

type certificate struct {
   attributes []cert_attr
   sec_level int
   source string
}

func (c certificate) lookup_tag(tag int) *cert_attr {
   for _, attr := range c.attributes {
      if attr.tag == tag {
         return &attr
      }
   }
   return nil
}

///

func (c certificate) get_seclevel() int {
   if c.source != "" {
      if c.sec_level == 0 {
         cert_attr attr=lookup_tag(TAG_IDS);
         if (attr!=null) {
            byte data[]=attr.data();
            ByteInput bi=new ByteInput(data);
            bi.set_pos(0x10);
            c.sec_level=bi.read_4();
         }
      }
   }
   return c.sec_level
}
