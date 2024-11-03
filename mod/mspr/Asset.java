/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS    */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,*/
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    */
/* SECURITY EXPLORATIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, */
/* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF  */
/* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE     */
/* SOFTWARE.                                                                  */

package mod.mspr;

import agsecres.tool.*;
import agsecres.helper.*;
import java.lang.*;
import java.util.*;
import java.io.*;

public class Asset {
   public static class Info {
      public static final String CURRENCY = "PLN";

      String attid;
      String atttitle;
      String atttitle_original;
      String attallow;
      String attyear;
      String attduration;
      String attprice;
      String attvat;
      String url;

      public void print() {
         PaddedPrinter pp = Shell.get_pp();

         if (attprice != null) pp.println("TVOD ASSET");
         else pp.println("ASSET");
         pp.pad(2, "");
         pp.println("id:             " + attid);
         pp.println("title:          " + atttitle);
         pp.println("title_original: " + atttitle_original);
         pp.println("allow:          " + attallow);
         pp.println("year:           " + attyear);
         pp.println("duration:       " + attduration);
         if (attprice != null) pp.println("price:          " + attprice + " " + CURRENCY);
         if (attvat != null) pp.println("vat:            " + attvat);
         pp.println("url:            " + url);
         pp.leave();
      }
   }

   public static final String ISM_EXTENSION = ".ism/";
   public static final int ISM_EXTENSION_SIZE = ISM_EXTENSION.length();

   String id;

   //base manifest url
   String url;

   //license server url
   String ls_url;

   //actual manifest url (possibly webcached)
   String manifest_url;

   //base download url for fragments
   String download_url;

   byte content_key[];

   public String id() {
      return id;
   }

   public String get_license() throws Throwable {

      Device curdev = Device.cur_device();
      ISMManifest ism = manifest();

      if (ism != null) {
         Shell.println("- generating license req");

         String wrmhdr = ism.get_wrmhdr_data();
         String req = MSPR.get_license_request(curdev, wrmhdr);
         return req;
      }

   }

   public static String cur_id() {
      return Vars.get_str("ASSETID");
   }

}
