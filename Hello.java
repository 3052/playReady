package agsecres.tool;

import agsecres.tool.Vars;
import mod.mspr.Device;
import mod.mspr.MSPR;

// Finally, as a proof for no importance of device identity such as SERIAL and
// MAC, a test was conducted that successfully obtained license to the asset
// with fake client device identity (fake `MAC` and `SERIAL` numbers):
// msprcp> set SERIAL DGBD0123456789ABC
// msprcp> set MAC AABBCCDDEEFF

public class Hello {
   
   static String wrm_hdr = """
<WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" version="4.0.0.0"><DATA><PROTECTINFO><KEYLEN>16</KEYLEN><ALGID>AESCTR</ALGID></PROTECTINFO><KID>UZ4Ci2rVvUSRD9S1/ZD7og==</KID></DATA></WRMHEADER>""";
   
   public static void main(String args[]) {
      Vars.set("MAC", "AABBCCDDEEFF");
      Vars.set("MSPR_DEBUG", 1);
      Vars.set("MSPR_FAKE_ROOT", 0);
      Vars.set("SECLEVEL", "SL2000");
      Vars.set("SERIAL", "DGBD0123456789ABC");
      
      Device cur_dev = Device.cur_device();
      
      try {
         String req = MSPR.get_license_request(cur_dev, wrm_hdr);
         System.out.println(req);
      } catch (Throwable err) {
         System.err.println(err);
      }
      
   }
   
}
