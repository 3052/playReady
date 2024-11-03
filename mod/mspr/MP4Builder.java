/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS    */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,*/
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    */
/* SECURITY EXPLORATIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, */
/* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF  */
/* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE     */
/* SOFTWARE.                                                                  */

package mod.mspr;

import agsecres.tool.*;
import java.lang.*;
import java.util.*;

public class MP4Builder {
   //public static class StreamsDesc {
   //   public static final String AUDIO_STREAM_START = "audio=";
   //   public static final String VIDEO_STREAM_START = "video=";

   //   String audio_name;
   //   String audio_quality;
   //   String video_quality;

   //   public StreamsDesc(String audio_name, String audio_quality, String video_quality) {
   //      this.audio_name = audio_name;
   //      this.audio_quality = audio_quality;
   //      this.video_quality = video_quality;
   //   }

   //   public String audio_name() {
   //      return audio_name;
   //   }

   //   public String audio_quality() {
   //      return audio_quality;
   //   }

   //   public String video_quality() {
   //      return video_quality;
   //   }

   //   public static StreamsDesc from_args(String audio_desc, String video_desc) {
   //      if (!audio_desc.startsWith(AUDIO_STREAM_START)) return null;
   //      audio_desc = audio_desc.substring(AUDIO_STREAM_START.length());

   //      if (!video_desc.startsWith(VIDEO_STREAM_START)) return null;
   //      video_desc = video_desc.substring(VIDEO_STREAM_START.length());

   //      String audio_params[] = Utils.tokenize(audio_desc, ".");

   //      if (audio_params.length != 2) return null;

   //      return new StreamsDesc(audio_params[0], audio_params[1], video_desc);
   //   }
   //}

   //public static class TimeDesc {
   //   public static final long SECS_IN_HOURS = 3600 L;
   //   public static final long SECS_IN_MINUTES = 60 L;

   //   //format is start_time+duration_time
   //   // where
   //   //          start_time is    [hh:[mm:]]ss
   //   //          duration_time is [hh:[mm:]]ss or empty

   //   //all time is represented in seconds
   //   long start_time;
   //   long duration;

   //   private static long parse_time_val(String timeval) {
   //      long val = Utils.long_value(timeval);

   //      if ((val >= 0) && (val < 60)) return val;

   //      return -1;
   //   }

   //   private static long parse_time(String time) {
   //      if (time.equals("")) return 0;

   //      String time_params[] = Utils.tokenize(time, ":");

   //      long val = -1;

   //      long hours = 0;
   //      long minutes = 0;
   //      long seconds = 0;

   //      try {
   //         switch (time_params.length) {
   //            //seconds
   //         case 1:
   //            seconds = parse_time_val(time_params[0]);
   //            break;
   //            //minutes, seconds
   //         case 2:
   //            minutes = parse_time_val(time_params[0]);
   //            seconds = parse_time_val(time_params[1]);
   //            break;
   //            //hours, minutes, seconds
   //         case 3:
   //            hours = parse_time_val(time_params[0]);
   //            minutes = parse_time_val(time_params[1]);
   //            seconds = parse_time_val(time_params[2]);
   //            break;
   //         default:
   //            hours = -1;
   //            break;
   //         }
   //      } catch (Throwable t) {}

   //      if ((hours < 0) | (minutes < 0) || (seconds < 0)) return -1;

   //      val = hours * SECS_IN_HOURS + minutes * SECS_IN_MINUTES + seconds;

   //      return val;
   //   }

   //   public TimeDesc(long start_time, long duration) {
   //      this.start_time = start_time;
   //      this.duration = duration;
   //   }

   //   public static TimeDesc from_arg(String time_desc) {
   //      String time_params[] = Utils.tokenize(time_desc, "+");

   //      if ((time_params.length != 1) && (time_params.length != 2)) return null;

   //      String s_time = "0";
   //      String s_duration = "0";

   //      switch (time_params.length) {
   //      case 2:
   //         s_duration = time_params[1];
   //      case 1:
   //         s_time = time_params[0];
   //         break;
   //      }

   //      long start_time = parse_time(s_time);
   //      long duration = parse_time(s_duration);

   //      if ((start_time < 0) || (duration < 0)) return null;

   //      return new TimeDesc(start_time, duration);
   //   }

   //   public long start_time() {
   //      return start_time;
   //   }

   //   public long duration() {
   //      return duration;
   //   }
   //}

   //public static MP4File.Box ftyp_box(String mbrand, String cbrands[]) {
   //   int major_brand = MP4File.str2int(mbrand);

   //   int compatible_brands[] = new int[cbrands.length];
   //   for (int i = 0; i < cbrands.length; i++) {
   //      compatible_brands[i] = MP4File.str2int(cbrands[i]);
   //   }

   //   int version = 1;

   //   return new MP4File.FTYP(major_brand, version, compatible_brands);
   //}

   //public static MP4File.Box mvhd_box(long creation_time, int timescale, long duration, int next_track) {
   //   byte version = 1;
   //   long modification_time = creation_time;

   //   int rate = 0x00010000;
   //   short volume = 0x0100;

   //   int unity_matrix[] = new int[] {
   //      0x00010000,
   //      0x00000000,
   //      0x00000000,
   //      0x00000000,
   //      0x00010000,
   //      0x00000000,
   //      0x00000000,
   //      0x00000000,
   //      0x40000000
   //   };

   //   return new MP4File.MVHD(version, creation_time, modification_time, timescale, duration, rate, volume, unity_matrix, next_track);
   //}

   //public static MP4File.Box tkhd_box(int track_id, long creation_time, long duration, int width, int height) {
   //   byte version = 1;
   //   //track enabled + track in movie
   //   int flags = 0x03;
   //   long modification_time = creation_time;
   //   short layer = 0;
   //   short alternate_group = 0;
   //   short volume = 0x0100;
   //   int matrix[] = new int[] {
   //      0x00010000,
   //      0x00000000,
   //      0x00000000,
   //      0x00000000,
   //      0x00010000,
   //      0x00000000,
   //      0x00000000,
   //      0x00000000,
   //      0x40000000
   //   };

   //   return new MP4File.TKHD(version, flags, creation_time, modification_time, track_id, duration, layer, alternate_group, volume, matrix, width, height);
   //}

   //public static MP4File.Box mdhd_box(long creation_time, int timescale, long duration, short language) {
   //   byte version = 1;
   //   long modification_time = creation_time;

   //   return new MP4File.MDHD(version, creation_time, modification_time, timescale, duration, language);
   //}

   //public static MP4File.Box hdlr_box(String handler_type, String name) {
   //   return new MP4File.HDLR(MP4File.str2int(handler_type), name);
   //}

   //public static MP4File.Box smhd_box(short balance) {
   //   return new MP4File.SMHD(balance);
   //}

   //public static MP4File.Box dref_box(MP4File.Box detable[]) {
   //   return new MP4File.DREF(detable);
   //}

   //public static MP4File.Box url_box(String location) {
   //   return new MP4File.URL(location);
   //}

   //public static MP4File.Box stts_box() {
   //   return new MP4File.STTS();
   //}

   //public static MP4File.Box ctts_box() {
   //   return new MP4File.CTTS();
   //}

   //public static MP4File.Box stsc_box() {
   //   return new MP4File.STSC();
   //}

   //public static MP4File.Box stsz_box() {
   //   return new MP4File.STSZ();
   //}

   //public static MP4File.Box stco_box() {
   //   return new MP4File.STCO();
   //}

   //public static MP4File.Box stsd_box(MP4File.SampleEntry entries[]) {
   //   return new MP4File.STSD(entries);
   //}

   //public static MP4File.Box mehd_box(long fragment_duration) {
   //   byte version = 1;

   //   return new MP4File.MEHD(version, fragment_duration);
   //}

   //public static MP4File.Box trex_box(int track_ID, int default_sample_description_index, int default_sample_duration, int default_sample_size, int default_sample_flags) {
   //   return new MP4File.TREX(track_ID, default_sample_description_index, default_sample_duration, default_sample_size, default_sample_flags);
   //}

   //public static MP4File.ContainerBox get_audio_track(int trackid, int track_num, long creation_time, int timescale, long duration,
   //   short language, Codec.Audio acodec, byte codec_prv_data[]) {
   //   MP4File.ContainerBox trak = MP4File.TRAK();

   //   //level 3
   //   int width = 0;
   //   int height = 0;
   //   MP4File.Box tkhd = tkhd_box(trackid, creation_time, duration, width, height);
   //   MP4File.ContainerBox mdia = MP4File.MDIA();
   //   trak.add_box(tkhd);
   //   trak.add_box(mdia);

   //   //level 4
   //   MP4File.Box mdhd = mdhd_box(creation_time, timescale, duration, language);
   //   MP4File.Box hdlr = hdlr_box("soun", "Sound");
   //   MP4File.ContainerBox minf = MP4File.MINF();

   //   mdia.add_box(mdhd);
   //   mdia.add_box(hdlr);
   //   mdia.add_box(minf);

   //   //level 5
   //   short balance = 0;
   //   MP4File.Box smhd = smhd_box(balance);
   //   MP4File.ContainerBox dinf = MP4File.DINF();
   //   MP4File.ContainerBox stbl = MP4File.STBL();

   //   minf.add_box(smhd);
   //   minf.add_box(dinf);
   //   minf.add_box(stbl);

   //   String location = "";
   //   MP4File.Box url = url_box(location);

   //   MP4File.Box dref = dref_box(new MP4File.Box[] {
   //      url
   //   });
   //   dinf.add_box(dref);

   //   //level 6
   //   MP4File.Box stts = stts_box();
   //   MP4File.Box ctts = ctts_box();
   //   MP4File.Box stsc = stsc_box();
   //   MP4File.Box stsz = stsz_box();
   //   MP4File.Box stco = stco_box();

   //   MP4File.SampleEntry se = acodec.get_sample_entry(codec_prv_data);
   //   MP4File.Box stsd = stsd_box(new MP4File.SampleEntry[] {
   //      se
   //   });

   //   stbl.add_box(stts);
   //   stbl.add_box(ctts);
   //   stbl.add_box(stsc);
   //   stbl.add_box(stsz);
   //   stbl.add_box(stco);
   //   stbl.add_box(stsd);

   //   return trak;
   //}

   //public static MP4File.ContainerBox get_video_track(int trackid, int track_num, long creation_time, int timescale, long duration,
   //   short language, Codec.Video vcodec, byte codec_prv_data[]) {
   //   MP4File.ContainerBox trak = MP4File.TRAK();

   //   //level 3
   //   int width = 0;
   //   int height = 0;
   //   MP4File.Box tkhd = tkhd_box(trackid, creation_time, duration, width, height);
   //   MP4File.ContainerBox mdia = MP4File.MDIA();
   //   trak.add_box(tkhd);
   //   trak.add_box(mdia);

   //   //level 4
   //   MP4File.Box mdhd = mdhd_box(creation_time, timescale, duration, language);
   //   MP4File.Box hdlr = hdlr_box("vide", "Video");
   //   MP4File.ContainerBox minf = MP4File.MINF();

   //   mdia.add_box(mdhd);
   //   mdia.add_box(hdlr);
   //   mdia.add_box(minf);

   //   //level 5
   //   short balance = 0;
   //   MP4File.Box smhd = smhd_box(balance);
   //   MP4File.ContainerBox dinf = MP4File.DINF();
   //   MP4File.ContainerBox stbl = MP4File.STBL();

   //   minf.add_box(smhd);
   //   minf.add_box(dinf);
   //   minf.add_box(stbl);

   //   String location = "";
   //   MP4File.Box url = url_box(location);

   //   MP4File.Box dref = dref_box(new MP4File.Box[] {
   //      url
   //   });
   //   dinf.add_box(dref);

   //   //level 6
   //   MP4File.Box stts = stts_box();
   //   MP4File.Box ctts = ctts_box();
   //   MP4File.Box stsc = stsc_box();
   //   MP4File.Box stsz = stsz_box();
   //   MP4File.Box stco = stco_box();

   //   MP4File.SampleEntry se = vcodec.get_sample_entry(codec_prv_data);
   //   MP4File.Box stsd = stsd_box(new MP4File.SampleEntry[] {
   //      se
   //   });

   //   stbl.add_box(stts);
   //   stbl.add_box(ctts);
   //   stbl.add_box(stsc);
   //   stbl.add_box(stsz);
   //   stbl.add_box(stco);
   //   stbl.add_box(stsd);

   //   return trak;
   //}

   //public static MP4File mp4file(String path, long creation_time, int timescale, long duration, int track_num, MP4File.ContainerBox audio_track) {
   //   //level 0
   //   MP4File mp4 = new MP4File(path);

   //   //level 1
   //   MP4File.Box ftyp = ftyp_box("isml", new String[] {
   //      "iso2",
   //      "piff"
   //   });
   //   MP4File.ContainerBox moov = MP4File.MOOV();
   //   mp4.add_box(ftyp);
   //   mp4.add_box(moov);

   //   //level 2
   //   MP4File.Box mvhd = mvhd_box(creation_time, timescale, duration, track_num + 1);
   //   MP4File.ContainerBox mvex = MP4File.MVEX();
   //   moov.add_box(mvhd);
   //   moov.add_box(audio_track);
   //   moov.add_box(mvex);

   //   MP4File.TKHD tkhd = (MP4File.TKHD) audio_track.lookup_box_by_name("tkhd");

   //   int track_id = tkhd.track_id();

   //   MP4File.Box mehd = mehd_box(duration);

   //   int default_sample_description_index = 1;
   //   int default_sample_duration = 0;
   //   int default_sample_size = 0;
   //   int default_sample_flags = 0;
   //   MP4File.Box trex = trex_box(track_id, default_sample_description_index, default_sample_duration, default_sample_size, default_sample_flags);

   //   mvex.add_box(mehd);
   //   mvex.add_box(trex);

   //   return mp4;
   //}

   //public static MP4File mp4file_av(String path, long creation_time, int timescale, long duration, int track_num, MP4File.ContainerBox audio_track, MP4File.ContainerBox video_track) {
   //   //level 0
   //   MP4File mp4 = new MP4File(path);

   //   //level 1
   //   MP4File.Box ftyp = ftyp_box("isml", new String[] {
   //      "iso2",
   //      "piff"
   //   });
   //   MP4File.ContainerBox moov = MP4File.MOOV();
   //   mp4.add_box(ftyp);
   //   mp4.add_box(moov);

   //   //level 2
   //   MP4File.Box mvhd = mvhd_box(creation_time, timescale, duration, track_num + 1);
   //   MP4File.ContainerBox mvex = MP4File.MVEX();
   //   moov.add_box(mvhd);
   //   moov.add_box(audio_track);
   //   moov.add_box(video_track);
   //   moov.add_box(mvex);

   //   MP4File.TKHD audio_tkhd = (MP4File.TKHD) audio_track.lookup_box_by_name("tkhd");
   //   int audio_track_id = audio_tkhd.track_id();

   //   MP4File.TKHD video_tkhd = (MP4File.TKHD) video_track.lookup_box_by_name("tkhd");
   //   int video_track_id = video_tkhd.track_id();

   //   MP4File.Box mehd = mehd_box(duration);

   //   int default_sample_description_index = 1;
   //   int default_sample_duration = 0;
   //   int default_sample_size = 0;
   //   int default_sample_flags = 0;

   //   MP4File.Box audio_trex = trex_box(audio_track_id, default_sample_description_index, default_sample_duration, default_sample_size, default_sample_flags);
   //   MP4File.Box video_trex = trex_box(video_track_id, default_sample_description_index, default_sample_duration, default_sample_size, default_sample_flags);

   //   mvex.add_box(mehd);
   //   mvex.add_box(audio_trex);
   //   mvex.add_box(video_trex);

   //   return mp4;
   //}
}
