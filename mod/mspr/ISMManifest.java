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
import org.w3c.dom.*;
import javax.xml.parsers.*;

public class ISMManifest {
   public static class SmoothStreamingMedia {
      String attMajorVersion;
      String attMinorVersion;
      String attTimeScale;
      String attDuration;

      public String MajorVersion() {
         return attMajorVersion;
      }

      public String MinorVersion() {
         return attMinorVersion;
      }

      public String TimeScale() {
         return attTimeScale;
      }

      public String Duration() {
         return attDuration;
      }

      public long real_duration() {
         long duration = Utils.long_value(attDuration);
         long timescale = Utils.long_value(attTimeScale);

         if ((duration < 0) || (timescale < 0)) return -1;

         return (long)(duration / timescale);
      }

   }

   public static class ProtectionHeader {
      String attSystemID;
      String data;
      String wrmhdr_data;
      WRMHeader wrmhdr;

      public String SystemID() {
         return attSystemID;
      }

      public String data() {
         return data;
      }

      public void set_data(String data) throws Throwable {
         this.data = data;
         this.wrmhdr_data = MSPR.wrmhdr_from_prothdr(data);
         this.wrmhdr = new WRMHeader(wrmhdr_data.getBytes());
      }

      public String wrmhdr_data() {
         return wrmhdr_data;
      }

      public WRMHeader wrmhdr() {
         return wrmhdr;
      }

      public void print() {
         PaddedPrinter pp = Shell.get_pp();

         pp.println("ProtectionHeader");
         pp.pad(2, "");
         pp.println("SystemID: " + attSystemID);
         wrmhdr.print();
         pp.leave();
      }
   }

   public static class QualityLevel {
      String attIndex;
      String attBitrate;
      String attFourCC;
      String attCodecPrivateData;
      byte CodecPrivateData[];

      public String Index() {
         return attIndex;
      }

      public String Bitrate() {
         return attBitrate;
      }

      public String FourCC() {
         return attFourCC;
      }

      public byte[] CodecPrivateData() {
         if (CodecPrivateData == null) {
            try {
               CodecPrivateData = Utils.parse_hex_string(attCodecPrivateData);
            } catch (Throwable t) {}
         }

         return CodecPrivateData;
      }

      public void print() {
         PaddedPrinter pp = Shell.get_pp();

         pp.println("QualityLevel");

         pp.pad(2, "");

         pp.println("Index:   " + attIndex);
         pp.println("Bitrate: " + attBitrate);
         pp.println("FourCC:  " + attFourCC);
         pp.println("CodecPrivateData: " + attCodecPrivateData);

         pp.leave();
      }
   }

   public static class AudioQualityLevel extends QualityLevel {
      String attSamplingRate;
      String attChannels;
      String attBitsPerSample;
      String attPacketSize;
      String attAudioTag;

      public String SamplingRate() {
         return attSamplingRate;
      }

      public String Channels() {
         return attChannels;
      }

      public String BitsPerSample() {
         return attBitsPerSample;
      }

      public String PacketSize() {
         return attPacketSize;
      }

      public String AudioTag() {
         return attAudioTag;
      }

      public void print() {
         PaddedPrinter pp = Shell.get_pp();

         super.print();

         pp.pad(2, "");

         pp.println("SamplingRate:  " + attSamplingRate);
         pp.println("Channels:      " + attChannels);
         pp.println("BitsPerSample: " + attBitsPerSample);
         pp.println("PacketSize:    " + attPacketSize);
         pp.println("AudioTag:      " + attAudioTag);

         pp.leave();
      }
   }

   public static class VideoQualityLevel extends QualityLevel {
      String attMaxWidth;
      String attMaxHeight;

      public String MaxWidth() {
         return attMaxWidth;
      }

      public String MaxHeight() {
         return attMaxHeight;
      }

      public void print() {
         PaddedPrinter pp = Shell.get_pp();

         super.print();

         pp.pad(2, "");

         pp.println("MaxWidth:        " + attMaxWidth);
         pp.println("MaxHeight:       " + attMaxHeight);

         pp.leave();
      }
   }

   public static class Chunk {
      String attt;
      String attd;

      long start_time_val = -1;

      public String start_time() {
         return attt;
      }

      public String duration() {
         return attd;
      }

      public long start_time_val() {
         if (start_time_val >= 0) return start_time_val;
         else
         if (attt != null) {
            return Utils.long_value(attt);
         }

         return 0;
      }

      public void set_start_time_val(long val) {
         start_time_val = val;
      }

      public long duration_val() {
         if (attd != null) {
            return Utils.long_value(attd);
         }

         return 0;
      }

      public void print() {
         PaddedPrinter pp = Shell.get_pp();

         pp.pad(2, "");

         if (attt != null) {
            pp.println("Duration: " + attd + " StartTime: " + attt);
         } else {
            pp.println("Duration: " + attd);
         }

         pp.leave();
      }
   }

   public static class StreamIndex {
      String attType;
      String attName;
      String attTimeScale;
      String attChunks;
      String attQualityLevels;
      String attUrl;

      Vector < QualityLevel > qlevels;
      Vector < Chunk > chunks;

      public StreamIndex() {
         qlevels = new Vector < QualityLevel > ();
         chunks = new Vector < Chunk > ();
      }

      public String Type() {
         return attType;
      }

      public String Name() {
         return attName;
      }

      public String TimeScale() {
         return attTimeScale;
      }

      public String Chunks() {
         return attChunks;
      }

      public String QualityLevels() {
         return attQualityLevels;
      }

      public String Url() {
         return attUrl;
      }

      public long timescale_val() {
         return Utils.long_value(attTimeScale);
      }

      public int ql_cnt() {
         return qlevels.size();
      }

      public QualityLevel get_ql(int i) {
         if (i < ql_cnt()) return qlevels.elementAt(i);

         return null;
      }

      public void add_ql(QualityLevel ql) {
         qlevels.add(ql);
      }

      public int chunk_cnt() {
         return chunks.size();
      }

      public Chunk get_chunk(int i) {
         if (i < chunk_cnt()) return chunks.elementAt(i);

         return null;
      }

      public void add_chunk(Chunk ch) {
         chunks.add(ch);
      }

      public int chunk_idx_by_time(long timeval) {
         long timepos = 0;

         for (int i = 0; i < chunk_cnt(); i++) {
            Chunk ch = get_chunk(i);

            long start_time = ch.start_time_val();
            long duration = ch.duration_val();

            if ((timepos <= timeval) && (timeval < (timepos + duration))) {
               return i;
            }

            timepos += duration;
         }

         return -1;
      }

      public long fragment_duration(int start_idx, int end_idx) {
         long duration = 0;

         for (int i = start_idx; i <= end_idx; i++) {
            Chunk ch = get_chunk(i);

            duration += ch.duration_val();
         }

         return duration;
      }

      public void print() {
         PaddedPrinter pp = Shell.get_pp();

         pp.println("StreamIndex");
         pp.pad(2, "");
         pp.println("Type:          " + attType);
         pp.println("Name:          " + attName);
         pp.println("TimeScale:     " + attTimeScale);
         pp.println("Chunks:        " + attChunks);
         pp.println("QualityLevels: " + attQualityLevels);
         pp.println("Url:           " + attUrl);

         for (int i = 0; i < ql_cnt(); i++) {
            pp.pad(2, "");
            QualityLevel ql = get_ql(i);
            ql.print();
            pp.leave();
         }

         pp.leave();
      }
   }

   public static final String BITRATE_VAR = "{bitrate}";
   public static final String STARTTIME_VAR = "{start time}";

   String path;
   byte data[];

   Document root;

   SmoothStreamingMedia ssm;
   ProtectionHeader ph;
   Vector < StreamIndex > streams;

   public int stream_cnt() {
      return streams.size();
   }

   public StreamIndex get_stream(int i) {
      if (i < stream_cnt()) return streams.elementAt(i);

      return null;
   }

   public ISMManifest(String path, byte data[]) throws Throwable {
      this.path = path;
      this.data = data;

      root = XmlUtils.parse_xml(new ByteArrayInputStream(data));

      Node ssm_node = XmlUtils.first_element(root, "SmoothStreamingMedia");

      if (ssm_node != null) {
         ssm = (SmoothStreamingMedia) XmlUtils.instance_from_node(SmoothStreamingMedia.class, ssm_node);
      }

      Node ph_node = XmlUtils.select_first(root, "SmoothStreamingMedia.Protection.ProtectionHeader");

      if (ph_node != null) {
         ph = (ProtectionHeader) XmlUtils.instance_from_node(ProtectionHeader.class, ph_node);

         String xml_data = XmlUtils.get_value(ph_node);

         if (xml_data != null) {
            ph.set_data(xml_data);
         }
      }

      Node si_nodes[] = XmlUtils.select(root, "SmoothStreamingMedia.StreamIndex");

      if (si_nodes != null) {
         streams = new Vector < StreamIndex > ();

         for (int i = 0; i < si_nodes.length; i++) {
            Node si_node = si_nodes[i];

            StreamIndex si = (StreamIndex) XmlUtils.instance_from_node(StreamIndex.class, si_node);
            streams.add(si);

            Node ql_nodes[] = XmlUtils.get_elements(si_node, "QualityLevel");

            if (ql_nodes != null) {
               for (int j = 0; j < ql_nodes.length; j++) {
                  Node ql_node = ql_nodes[j];

                  QualityLevel ql = null;

                  if (si.Type().equals("audio")) {
                     ql = (QualityLevel) XmlUtils.instance_from_node(AudioQualityLevel.class, ql_node);
                  } else

                  if (si.Type().equals("video")) {
                     ql = (QualityLevel) XmlUtils.instance_from_node(VideoQualityLevel.class, ql_node);
                  }

                  if (ql != null) {
                     si.add_ql(ql);
                  }
               }
            }

            Node ch_nodes[] = XmlUtils.get_elements(si_node, "c");

            if (ch_nodes != null) {
               long start_time = 0;

               for (int j = 0; j < ch_nodes.length; j++) {
                  Node ch_node = ch_nodes[j];

                  Chunk chunk = (Chunk) XmlUtils.instance_from_node(Chunk.class, ch_node);
                  si.add_chunk(chunk);

                  chunk.set_start_time_val(start_time);

                  start_time += chunk.duration_val();
               }
            }
         }
      }
   }

   public String get_wrmhdr_data() {
      return ph.wrmhdr_data();
   }

   public WRMHeader get_wrmhdr() {
      return ph.wrmhdr();
   }

   public StreamIndex get_stream(String type, String name) {
      for (int i = 0; i < stream_cnt(); i++) {
         StreamIndex si = get_stream(i);

         if (si.Type().equals(type)) {
            if (name == null) return si;

            if (si.Name().equals(name)) return si;
         }
      }

      return null;
   }

   public StreamIndex get_stream(String type) {
      return get_stream(type, null);
   }

   public StreamIndex get_audio_stream(String name) {
      return get_stream("audio", name);
   }

   public StreamIndex get_video_stream() {
      return get_stream("video");
   }

   public long duration() {
      return Utils.long_value(ssm.Duration());
   }

   public int timescale() {
      return Utils.int_value(ssm.TimeScale());
   }

   public long real_duration() {
      return ssm.real_duration();
   }

   public static ISMManifest from_file(String path) throws Throwable {
      byte data[] = Utils.load_file(path);

      if (data != null) {
         return new ISMManifest(path, data);
      }

      return null;
   }

   public AudioQualityLevel get_audio_ql(String name, String quality_idx) {
      StreamIndex si = get_stream("audio", name);

      if (si != null) {
         for (int i = 0; i < si.ql_cnt(); i++) {
            QualityLevel ql = si.get_ql(i);

            String index = ql.Index();

            if (index.equals(quality_idx)) return (AudioQualityLevel) ql;
         }
      }

      return null;
   }

   public VideoQualityLevel get_video_ql(String quality_idx) {
      StreamIndex si = get_stream("video");

      if (si != null) {
         for (int i = 0; i < si.ql_cnt(); i++) {
            QualityLevel ql = si.get_ql(i);

            String index = ql.Index();

            if (index.equals(quality_idx)) return (VideoQualityLevel) ql;
         }
      }

      return null;
   }

   private static String build_frag_url(String url, long start_time, String bitrate) {

      if (url.contains(STARTTIME_VAR)) {
         url = url.replace(STARTTIME_VAR, "" + start_time);
      }

      if (url.contains(BITRATE_VAR)) {
         url = url.replace(BITRATE_VAR, bitrate);
      }

      return url;
   }

   public String get_video_frag_url(int idx, String quality) {
      ISMManifest.StreamIndex video_stream = get_stream("video");
      ISMManifest.VideoQualityLevel vql = get_video_ql(quality);

      Chunk chunk = video_stream.get_chunk(idx);
      long start_time = chunk.start_time_val();

      String base_url = video_stream.Url();
      String bitrate = vql.Bitrate();

      return build_frag_url(base_url, start_time, bitrate);
   }

   public void print() {
      PaddedPrinter pp = Shell.get_pp();

      pp.println("MANIFEST: " + path);
      pp.pad(2, "");
      ssm.print();
      pp.leave();

      pp.pad(2, "");
      ph.print();
      pp.leave();

      for (int i = 0; i < stream_cnt(); i++) {
         pp.pad(2, "");
         StreamIndex si = get_stream(i);
         si.print();
         pp.leave();
      }
   }
}
