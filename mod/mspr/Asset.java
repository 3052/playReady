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
import mod.cdn.*;
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

   MP4Builder.StreamsDesc sd;
   MP4Builder.TimeDesc td;

   ISMManifest ism;
   License license;

   byte content_key[];

   Codec.Audio audio_codec;
   Codec.Video video_codec;

   void load_url() {
      String urlfile = FileCache.url_filename(id);

      byte data[] = Utils.load_file(urlfile);

      if (data != null) {
         url = new String(data).trim();
      }
   }

   void load_ls_url() {
      String lsurlfile = FileCache.lsurl_filename(id);

      byte data[] = Utils.load_file(lsurlfile);

      if (data != null) {
         ls_url = new String(data).trim();
      }
   }

   void load_key() {
      String keyfile = FileCache.key_filename(id);

      byte data[] = Utils.load_file(keyfile);

      if (data != null) {
         Shell.println("- loading cached content key");

         String hexkey = new String(data).trim();

         content_key = Utils.parse_hex_string(hexkey);
      }
   }

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

   public Asset(String id, MP4Builder.StreamsDesc sd, MP4Builder.TimeDesc td) {
      this.id = id;
      this.sd = sd;
      this.td = td;

      String dir = FileCache.asset_dir(id);

      if (!Utils.file_exists(dir)) {
         FileCache.make_dirs(id);
      }
   }

   public Asset(String id) {
      this(id, null, null);
   }

   public String id() {
      return id;
   }

   public String url() {
      if (url == null) {
         load_url();
      }

      return url;
   }

   public String ls_url() {
      if (ls_url == null) {
         load_ls_url();
      }

      return ls_url;
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

   public MP4Builder.StreamsDesc sd() {
      return sd;
   }

   public MP4Builder.TimeDesc td() {
      return td;
   }

   public ISMManifest manifest() throws Throwable {
      if (ism == null) {
         String manpath = FileCache.manifest_filename(id);

         if (!Utils.file_exists(manpath)) {
            Device curdev = Device.cur_device();

            Shell.println("- downloading manifest");
            CDN.download_content(curdev.get_serial(), url(), manpath);
         } else {
            Shell.println("- loading cached manifest");
         }

         ism = ISMManifest.from_file(manpath);
      }

      return ism;
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

   public Info get_info() throws Throwable {
      String infofile = FileCache.info_filename(id);

      if (Utils.file_exists(infofile)) {
         byte data[] = Utils.load_file(infofile);

         String xml = new String(data);

         JSON.JSONObject root = JSON.parse(xml);

         JSON.JSONObject content = JSON.get_bucket(root, "content");

         Info info = (Info) JSON.instance_from_node(Info.class, content);
         info.url = JSON.get_string(root, "stream_low");

         return info;
      }

      return null;
   }

   public byte[] content_key() throws Throwable {
      if (content_key == null) {
         load_key();

         if (content_key == null) {
            License license = get_license();

            cache_key(license.get_content_key());
         }
      }

      return content_key;
   }

   public static String cur_id() {
      return Vars.get_str("ASSETID");
   }

   public int fragment_cnt(String audio_name, String audio_quality, String video_quality, int start_idx, int end_idx) throws Throwable {
      int cnt = 0;

      for (int idx = start_idx; idx <= end_idx; idx++) {
         if (!FileCache.fragment_exists(id, audio_name, audio_quality, video_quality, idx)) break;
         cnt++;
      }

      return cnt;
   }

   public MP4File[] get_fragment(String audio_name, String audio_quality, String video_quality, int idx) throws Throwable {
      String vfragpath = FileCache.video_filename(id, video_quality, idx);
      String afragpath = FileCache.audio_filename(id, audio_name, audio_quality, idx);

      if (Utils.file_exists(vfragpath) && Utils.file_exists(afragpath)) {
         MP4File audio_frag = MP4File.from_file(afragpath);
         MP4File video_frag = MP4File.from_file(vfragpath);

         audio_frag.decrypt(audio_codec, content_key());
         video_frag.decrypt(video_codec, content_key());

         return new MP4File[] {
            audio_frag,
            video_frag
         };
      }

      return null;
   }

   public MP4File create_mp4file(String audio_name, String audio_quality, String video_quality, int audio_track_id, int video_track_id, long duration) throws Throwable {
      String path = FileCache.mp4_filename(id);

      long creation_time = Utils.current_date();

      ISMManifest ism = manifest();

      int timescale = ism.timescale();
      short language = 0x0000;

      int track_num = 2;

      //audio codec
      ISMManifest.AudioQualityLevel aql = ism.get_audio_ql(audio_name, audio_quality);

      short channel_count = (short) Utils.int_value(aql.Channels());
      short sample_size = (short) Utils.int_value(aql.BitsPerSample());
      int sample_rate = Utils.int_value(aql.SamplingRate());

      byte acodec_prv_data[] = aql.CodecPrivateData();
      audio_codec = Codec.Audio.get(Codec.AACL_CODEC, channel_count, sample_size, sample_rate);
      MP4File.ContainerBox audio_track = MP4Builder.get_audio_track(audio_track_id, track_num, creation_time, timescale, duration, language,
         audio_codec, acodec_prv_data);

      ISMManifest.VideoQualityLevel vql = ism.get_video_ql(video_quality);

      short width = (short) Utils.int_value(vql.MaxWidth());
      short height = (short) Utils.int_value(vql.MaxHeight());

      byte vcodec_prv_data[] = vql.CodecPrivateData();

      video_codec = Codec.Video.get(Codec.AVC1_CODEC, width, height);
      MP4File.ContainerBox video_track = MP4Builder.get_video_track(video_track_id, track_num, creation_time, timescale, duration, language,
         video_codec, vcodec_prv_data);

      MP4File genmp4 = MP4Builder.mp4file_av(path, creation_time, timescale, duration, track_num, audio_track, video_track);

      return genmp4;
   }

}
