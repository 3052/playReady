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

   public String download_url() {
      if (download_url == null) {
         if (manifest_url() != null) {
            int idx = manifest_url().indexOf(ISM_EXTENSION);

            if (idx > 0) {
               download_url = manifest_url().substring(0, idx + ISM_EXTENSION_SIZE);
            }
         }
      }

      return download_url;
   }

   public String id() {
      return id;
   }

   public String manifest_url() {
      if (manifest_url == null) {
         Device curdev = Device.cur_device();

         Web.PathInfo pi = CDN.get_pathinfo(curdev.get_serial(), url());

         if (pi != null) {
            manifest_url = pi.actual_url();
         }
      }

      return manifest_url;
   }

   public void cache_key(byte content_key[]) throws Throwable {
      String keyfile = FileCache.key_filename(id);
      String keydata = Utils.construct_hex_string(content_key);

      Utils.save_file(keyfile, keydata.getBytes());
   }

   // KEEP
   public License get_license() throws Throwable {
      if (license == null) {
         String license_file = FileCache.local_license_filename(id);

         if ((license_file != null) && Utils.file_exists(license_file)) {
            Shell.println("- using local license [" + license_file + "]");

            byte license_xml[] = Utils.load_file(license_file);

            license = new License(license_xml);
         } else {
            Device curdev = Device.cur_device();

            ISMManifest ism = manifest();

            if (ism != null) {
               Shell.println("- generating license req");

               String wrmhdr = ism.get_wrmhdr_data();
               String req = MSPR.get_license_request(curdev, wrmhdr);

               String debugfile = FileCache.debug_file(id, "lic_req.txt");
               Utils.save_file(debugfile, req.getBytes());

               String ls_url = ls_url();

               if (ls_url != null) {
                  Shell.println("- sending license req to: " + ls_url);

                  String resp = LS.send_license_req(ls_url, curdev, req);
                  byte license_xml[] = resp.getBytes();

                  debugfile = FileCache.debug_file(id, "lic_resp.txt");
                  Utils.save_file(debugfile, license_xml);

                  try {
                     license = new License(license_xml);
                  } catch (Throwable t) {}

                  if (license == null) {
                     Shell.report_error("cannot get license, see [" + debugfile + "] for information");
                  }
               }
            } else {
               String manpath = FileCache.manifest_filename(id);
               Shell.report_error("invalid assetid or Manifest not present [" + manpath + "]");
            }
         }
      }

      if (license != null) cache_key(license.get_content_key());

      return license;
   }

   public static String cur_id() {
      return Vars.get_str("ASSETID");
   }

}
