package playReady

type certificate struct{}

int get_seclevel() {
   if ((source!=null)&&(seclevel==0)) {
      CertAttr attr=lookup_tag(TAG_IDS);
      if (attr!=null) {
         byte data[]=attr.data();
         ByteInput bi=new ByteInput(data);
         bi.set_pos(0x10);
         seclevel=bi.read_4();
      }
   }
   return seclevel;
}
