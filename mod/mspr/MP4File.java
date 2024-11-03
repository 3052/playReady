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
import java.text.*;

public class MP4File {
   //public static final String ROOT_MP4_NAME = "MP4 FILE";

   //public static final int CONTAINER_BOX = -1;

   //public static final int BYTEOUTPUT_SIZE = 0x100000;

   ////supported MPEG-4 box types
   //public static final int MOOF_BOX = 0x6D6F6F66;
   //public static final int MFHD_BOX = 0x6D666864;
   //public static final int TRAF_BOX = 0x74726166;
   //public static final int TFHD_BOX = 0x74666864;
   //public static final int TRUN_BOX = 0x7472756E;
   //public static final int UUID_BOX = 0x75756964;
   //public static final int MDAT_BOX = 0x6D646174;

   ////for file generation
   //public static final int MOOV_BOX = 0x6D6F6F76;
   //public static final int TRAK_BOX = 0x7472616B;
   //public static final int MDIA_BOX = 0x6D646961;
   //public static final int MINF_BOX = 0x6D696E66;
   //public static final int STBL_BOX = 0x7374626C;
   //public static final int MVEX_BOX = 0x6D766578;

   //public static final int FTYP_BOX = 0x66747970;
   //public static final int MVHD_BOX = 0x6D766864;
   //public static final int TKHD_BOX = 0x746B6864;
   //public static final int MDHD_BOX = 0x6D646864;
   //public static final int HDLR_BOX = 0x68646C72;
   //public static final int SMHD_BOX = 0x736D6864;
   //public static final int DINF_BOX = 0x64696E66;
   //public static final int STTS_BOX = 0x73747473;
   //public static final int CTTS_BOX = 0x63747473;
   //public static final int STSC_BOX = 0x73747363;
   //public static final int STSZ_BOX = 0x7374737A;
   //public static final int STCO_BOX = 0x7374636F;
   //public static final int STSD_BOX = 0x73747364;
   //public static final int URL_BOX = 0x75726C20;
   //public static final int DREF_BOX = 0x64726566;
   //public static final int TREX_BOX = 0x74726578;
   //public static final int MEHD_BOX = 0x6D656864;

   ////for audio and video sample entry boxes
   //public static final int MP4A_BOX = 0x6D703461;
   //public static final int ESDS_BOX = 0x65736473;

   //public static final int AVC1_BOX = 0x61766331;
   //public static final int AVCC_BOX = 0x61766343;

   ////handler types
   //public static final int HANDLER_SOUND = 0x736f756e;
   //public static final int HANDLER_VIDEO = 0x76696465;

   ////supported codecs
   //public static final int AACL_CODEC = 0x1;
   //public static final int AVC1_CODEC = 0x2;

   ////Box hdr length
   //public static final int BOX_HDR_SIZE = 8;

   //String path;
   //ContainerBox cbox;

   //static String box_desc(int box) {
   //   switch (box) {
   //   case MOOF_BOX:
   //      return "Movie Fragment Box";
   //   case MFHD_BOX:
   //      return "Movie Fragment Header Box";
   //   case TRAF_BOX:
   //      return "Track Fragment Box";
   //   case TFHD_BOX:
   //      return "Track Fragment Header Box";
   //   case TRUN_BOX:
   //      return "Track Fragment Run Box";
   //   case UUID_BOX:
   //      return "Usertype Box";
   //   case MDAT_BOX:
   //      return "Media Data Box";
   //   case MOOV_BOX:
   //      return "Movie Box";
   //   case TRAK_BOX:
   //      return "Track Box";
   //   case MDIA_BOX:
   //      return "Media Box";
   //   case MINF_BOX:
   //      return "Media Information Box";
   //   case STBL_BOX:
   //      return "Sample Table Box";
   //   case MVEX_BOX:
   //      return "Movie Extends Box";
   //   case FTYP_BOX:
   //      return "File Type Box";
   //   case MVHD_BOX:
   //      return "Movie Header Box";
   //   case TKHD_BOX:
   //      return "Track Header Box";
   //   case MDHD_BOX:
   //      return "Media Header Box";
   //   case HDLR_BOX:
   //      return "Handler Reference Box";
   //   case SMHD_BOX:
   //      return "Sound Media Header Box";
   //   case DINF_BOX:
   //      return "Data Information Box";
   //   case STTS_BOX:
   //      return "Decoding Time to Sample Box";
   //   case CTTS_BOX:
   //      return "Composition Time to Sample Box";
   //   case STSC_BOX:
   //      return "Sample To Chunk Box";
   //   case STSZ_BOX:
   //      return "Sample Size Boxes";
   //   case STCO_BOX:
   //      return "Chunk Offset Box";
   //   case STSD_BOX:
   //      return "Sample Description Box";
   //   case DREF_BOX:
   //      return "Data Reference Box";
   //   case TREX_BOX:
   //      return "Track Extends Box";
   //   case MEHD_BOX:
   //      return "Movie Extends Header Box";
   //   }

   //   return null;
   //}

   //public static class Box {
   //   Box parent;
   //   //the length of data without hdr
   //   int len;
   //   int type;
   //   String name;

   //   byte data[];

   //   public Box(ByteInput bi) {
   //      if (bi != null) {
   //         len = bi.read_4() - BOX_HDR_SIZE;

   //         type = bi.read_4();
   //         data = bi.read_n(len);
   //      }
   //   }

   //   public Box(Box parent, int len, int type, byte data[]) {
   //      this.parent = parent;
   //      this.len = len;
   //      this.type = type;
   //      this.data = data;
   //   }

   //   public Box(Box parent, int type) {
   //      this(parent, 0, type, null);
   //   }

   //   public Box(int type) {
   //      this(null, 0, type, null);
   //   }

   //   public Box parent() {
   //      return parent;
   //   }

   //   public int len() {
   //      return len;
   //   }

   //   public int type() {
   //      return type;
   //   }

   //   public byte[] data() {
   //      return data;
   //   }

   //   public String name() {
   //      if (name == null) {
   //         name = int2str(type);
   //      }

   //      return name;
   //   }

   //   public int get_lvl() {
   //      int lvl = 0;

   //      Box p = parent();

   //      while (p != null) {
   //         p = p.parent();
   //         lvl++;
   //      }

   //      return lvl;
   //   }

   //   public String full_name() {
   //      String fname = get_lvl() + " " + name();

   //      String desc = box_desc(type);

   //      if (desc != null) {
   //         fname += " [" + desc + "]";
   //      }

   //      return fname;
   //   }

   //   public void set_parent(Box parent) {
   //      this.parent = parent;
   //   }

   //   public void changed() {
   //      this.data = null;

   //      if (parent != null) parent.changed();
   //   }

   //   public static Box parse(MP4File mp4, Box parent, Box b) {
   //      switch (b.type()) {
   //      case MOOF_BOX:
   //      case TRAF_BOX:
   //      case MOOV_BOX:
   //      case TRAK_BOX:
   //      case MDIA_BOX:
   //      case MINF_BOX:
   //      case STBL_BOX:
   //      case MVEX_BOX:
   //      case DINF_BOX:
   //         return ContainerBox.get(mp4, parent, b.name(), b.type(), b.data());
   //      case TRUN_BOX:
   //         return TRUN.get(mp4, parent, b.data());
   //      case UUID_BOX:
   //         return UUID.get(mp4, parent, b.data());
   //      case MDAT_BOX:
   //         return MDAT.get(mp4, parent, b.data());

   //         //mandatory boxes (required for Microsoft samples parsing and MP4 file creation)
   //      case FTYP_BOX:
   //         return FTYP.get(mp4, parent, b.data());
   //      case MVHD_BOX:
   //         return MVHD.get(mp4, parent, b.data());
   //      case TKHD_BOX:
   //         return TKHD.get(mp4, parent, b.data());
   //      case MDHD_BOX:
   //         return MDHD.get(mp4, parent, b.data());
   //      case HDLR_BOX:
   //         return HDLR.get(mp4, parent, b.data());
   //      case SMHD_BOX:
   //         return SMHD.get(mp4, parent, b.data());
   //      case STTS_BOX:
   //         return STTS.get(mp4, parent, b.data());
   //      case CTTS_BOX:
   //         return CTTS.get(mp4, parent, b.data());
   //      case STSC_BOX:
   //         return STSC.get(mp4, parent, b.data());
   //      case STSZ_BOX:
   //         return STSZ.get(mp4, parent, b.data());
   //      case STCO_BOX:
   //         return STCO.get(mp4, parent, b.data());
   //      case STSD_BOX:
   //         return STSD.get(mp4, parent, b.data());
   //      case MP4A_BOX:
   //         return MP4A.get(mp4, parent, b.data());
   //      case AVC1_BOX:
   //         return AVC1.get(mp4, parent, b.data());
   //      case TREX_BOX:
   //         return TREX.get(mp4, parent, b.data());
   //      case MEHD_BOX:
   //         return MEHD.get(mp4, parent, b.data());
   //      case TFHD_BOX:
   //         return TFHD.get(mp4, parent, b.data());

   //      case DREF_BOX:
   //         return DREF.get(mp4, parent, b.data());
   //      case URL_BOX:
   //         return URL.get(mp4, parent, b.data());
   //      }

   //      return b;
   //   }

   //   public String stype() {
   //      String s = name();

   //      s += " [" + Utils.hex_value(type, 8) + "]";

   //      return s;
   //   }

   //   public void write_data(ByteOutput bo) {
   //      ERR.log("unimplemented write for " + name() + " Box");
   //   }

   //   public void write(ByteOutput bo) {
   //      byte data[] = data();

   //      if (data != null) {
   //         bo.write_4(len() + BOX_HDR_SIZE);
   //         bo.write_4(type());
   //         bo.write_n(data);
   //      } else {
   //         ByteOutput bos = new ByteOutput(BYTEOUTPUT_SIZE);
   //         write_data(bos);

   //         byte box_data[] = bos.bytes();
   //         int box_len = box_data.length;

   //         bo.write_4(box_len + BOX_HDR_SIZE);
   //         bo.write_4(type());
   //         bo.write_n(box_data);
   //      }
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());

   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(len(), 8));
   //         pp.printhex("data", data());
   //      }
   //   }
   //}

   //public static class ContainerBox extends Box {
   //   Vector < Box > boxes;

   //   public ContainerBox(String name) {
   //      super(null);

   //      this.name = name;
   //      this.boxes = new Vector < Box > ();
   //   }

   //   public ContainerBox(int type) {
   //      super(type);

   //      this.boxes = new Vector < Box > ();
   //   }

   //   public ContainerBox(Box parent, String name, int len, int type, byte data[], Vector < Box > boxes) {
   //      super(parent, len, type, data);

   //      this.name = name;
   //      this.boxes = boxes;
   //   }

   //   public int cnt() {
   //      return boxes.size();
   //   }

   //   public Box get(int i) {
   //      if (i < cnt()) {
   //         return boxes.elementAt(i);
   //      }

   //      return null;
   //   }

   //   public void add_box(Box b) {
   //      boxes.add(b);

   //      if (b.parent() == null) b.set_parent(this);
   //   }

   //   public static Box get(MP4File mp4, Box parent, String name, int type, byte data[]) {
   //      Vector < Box > boxes = read_boxes(data);

   //      if (boxes.size() > 0) {
   //         if (boxes.size() == 1) {
   //            return Box.parse(mp4, parent, boxes.elementAt(0));
   //         } else {
   //            Vector < Box > new_boxes = new Vector < Box > ();

   //            int len = data.length;

   //            //     if (type!=CONTAINER_BOX) len+=8;

   //            ContainerBox container = new ContainerBox(parent, name, len, type, data, new_boxes);

   //            for (int i = 0; i < boxes.size(); i++) {
   //               Box box = boxes.elementAt(i);
   //               Box new_box = Box.parse(mp4, container, box);

   //               new_boxes.add(new_box);
   //            }

   //            return container;
   //         }
   //      }

   //      return null;
   //   }

   //   public Box lookup_box_by_name(String name) {
   //      for (int i = 0; i < cnt(); i++) {
   //         Box box = get(i);

   //         if (box.name().equals(name)) return box;
   //      }

   //      return null;
   //   }

   //   public Box lookup_box_by_type(int type) {
   //      for (int i = 0; i < cnt(); i++) {
   //         Box box = get(i);

   //         if (box.type() == type) return box;
   //      }

   //      return null;
   //   }

   //   public static Box read_box(byte data[]) {
   //      return read_boxes(data).elementAt(0);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      for (int i = 0; i < cnt(); i++) {
   //         Box box = get(i);
   //         box.write(bo);
   //      }
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      pp.println("len: " + Utils.hex_value(data.length, 8));
   //      pp.pad(2, "");

   //      for (int i = 0; i < boxes.size(); i++) {
   //         Box box = boxes.elementAt(i);

   //         box.print(verbose);
   //      }

   //      pp.leave();
   //   }
   //}

   //public static class MDAT extends Box {
   //   public MDAT(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, MDAT_BOX, data);
   //   }

   //   public static MDAT get(MP4File mp4, Box parent, byte data[]) {
   //      return new MDAT(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_n(data);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");
   //         pp.printhex("data", data);
   //         pp.leave();
   //      }
   //   }
   //}

   //public static class UUID extends Box {
   //   public static final int UUID_SIZE = 0x10;

   //   byte uuid[];
   //   byte user_data[];

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      ByteInput bi = new ByteInput(data);

   //      byte uuid[] = bi.peek_n(UUID_SIZE);

   //      if (SampleEncryptionBox.uuid_match(uuid)) return new SampleEncryptionBox(mp4, parent, data.length, UUID_BOX, data);

   //      return new UUID(mp4, parent, data);
   //   }

   //   public UUID(MP4File mp4, Box parent, byte data[]) {
   //      this(mp4, parent, data.length, UUID_BOX, data);
   //   }

   //   public UUID(MP4File mp4, Box parent, String name, int len, int type, byte data[]) {
   //      super(parent, len, type, data);

   //      ByteInput bi = new ByteInput(data);

   //      uuid = bi.read_n(UUID_SIZE);
   //      user_data = bi.read_n(data.length - UUID_SIZE);

   //      this.name = name;
   //   }

   //   public UUID(MP4File mp4, Box parent, int len, int type, byte data[]) {
   //      super(parent, len, type, data);

   //      ByteInput bi = new ByteInput(data);

   //      uuid = bi.read_n(UUID_SIZE);
   //      user_data = bi.read_n(data.length - UUID_SIZE);

   //      this.name = "uuid_" + Utils.construct_hex_string(uuid);
   //   }

   //   public byte[] uuid() {
   //      return uuid;
   //   }

   //   public byte[] user_data() {
   //      return user_data;
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_n(uuid);
   //      bo.write_n(user_data);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //      }
   //   }
   //}

   //public static class SampleInfo {
   //   public static final int INVALID_VALUE = -1;

   //   int duration;
   //   int size;
   //   int flags;
   //   int composition_time_offset;

   //   public SampleInfo(int duration, int size, int flags, int composition_time_offset) {
   //      this.duration = duration;
   //      this.size = size;
   //      this.flags = flags;
   //      this.composition_time_offset = composition_time_offset;
   //   }

   //   public int duration() {
   //      return duration;
   //   }

   //   public int size() {
   //      return size;
   //   }

   //   public int flags() {
   //      return flags;
   //   }

   //   public int composition_time_offset() {
   //      return composition_time_offset;
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      if (verbose) {
   //         pp.pad(2, "");
   //         if (duration != INVALID_VALUE) {
   //            pp.println("duration:                " + Utils.hex_value(duration, 8));
   //         }
   //         if (size != INVALID_VALUE) {
   //            pp.println("size:                    " + Utils.hex_value(size, 8));
   //         }
   //         if (flags != INVALID_VALUE) {
   //            pp.println("flags:                   " + Utils.hex_value(flags, 8));
   //         }
   //         if (composition_time_offset != INVALID_VALUE) {
   //            pp.println("composition_time_offset: " + Utils.hex_value(composition_time_offset, 8));
   //         }
   //         pp.leave();
   //      }
   //   }
   //}

   //public static class TRUN extends Box {
   //   public static final int FLAG_DATA_OFFSET_PRESENT = 0x001;
   //   public static final int FLAG_FIRST_SAMPLE_FLAGS_PRESENT = 0x004;
   //   public static final int FLAG_SAMPLE_DURATION_PRESENT = 0x100;
   //   public static final int FLAG_SAMPLE_SIZE_PRESENT = 0x200;
   //   public static final int FLAG_SAMPLE_FLAGS_PRESENT = 0x400;
   //   public static final int FLAG_SAMPLE_COMPOSITION_TIME_PRESENT = 0x800;

   //   int tr_flags;
   //   int sample_cnt;

   //   //optional fields
   //   int data_offset;
   //   int first_sample_flags;

   //   Vector < SampleInfo > sinfo;

   //   public int sample_cnt() {
   //      return sample_cnt;
   //   }

   //   public SampleInfo get_sinfo(int idx) {
   //      if (idx < sample_cnt()) return sinfo.elementAt(idx);
   //      else return null;
   //   }

   //   public boolean flag(int val) {
   //      if ((tr_flags & val) == val) return true;
   //      else return false;
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new TRUN(mp4, parent, data);
   //   }

   //   public Vector < SampleInfo > parse_samples_info(ByteInput bi, int cnt) {
   //      Vector < SampleInfo > sinfo = new Vector < SampleInfo > ();

   //      for (int i = 0; i < cnt; i++) {
   //         int duration = SampleInfo.INVALID_VALUE;
   //         int size = SampleInfo.INVALID_VALUE;
   //         int flags = SampleInfo.INVALID_VALUE;
   //         int composition_time_offset = SampleInfo.INVALID_VALUE;

   //         if (flag(FLAG_SAMPLE_DURATION_PRESENT)) duration = bi.read_4();
   //         if (flag(FLAG_SAMPLE_SIZE_PRESENT)) size = bi.read_4();
   //         if (flag(FLAG_SAMPLE_FLAGS_PRESENT)) flags = bi.read_4();
   //         if (flag(FLAG_SAMPLE_COMPOSITION_TIME_PRESENT)) composition_time_offset = bi.read_4();

   //         SampleInfo si = new SampleInfo(duration, size, flags, composition_time_offset);
   //         sinfo.add(si);
   //      }

   //      return sinfo;
   //   }

   //   public TRUN(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, TRUN_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      tr_flags = bi.read_4();
   //      sample_cnt = bi.read_4();

   //      if (flag(FLAG_DATA_OFFSET_PRESENT)) data_offset = bi.read_4();
   //      if (flag(FLAG_FIRST_SAMPLE_FLAGS_PRESENT)) first_sample_flags = bi.read_4();

   //      sinfo = parse_samples_info(bi, sample_cnt);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_4(tr_flags);
   //      bo.write_4(sample_cnt);

   //      if (flag(FLAG_DATA_OFFSET_PRESENT)) bo.write_4(data_offset);
   //      if (flag(FLAG_FIRST_SAMPLE_FLAGS_PRESENT)) bo.write_4(first_sample_flags);

   //      for (int i = 0; i < sample_cnt; i++) {
   //         SampleInfo si = get_sinfo(i);

   //         if (flag(FLAG_SAMPLE_DURATION_PRESENT)) bo.write_4(si.duration);
   //         if (flag(FLAG_SAMPLE_SIZE_PRESENT)) bo.write_4(si.size);
   //         if (flag(FLAG_SAMPLE_FLAGS_PRESENT)) bo.write_4(si.flags);
   //         if (flag(FLAG_SAMPLE_COMPOSITION_TIME_PRESENT)) bo.write_4(si.composition_time_offset);
   //      }
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));

   //         pp.pad(2, "");
   //         pp.println("tr_flags:   " + Utils.hex_value(tr_flags, 8));
   //         pp.println("sample_cnt: " + Utils.hex_value(sample_cnt, 8));

   //         for (int i = 0; i < sample_cnt(); i++) {
   //            SampleInfo si = get_sinfo(i);

   //            si.print(verbose);
   //         }
   //         pp.leave();
   //      }
   //   }
   //}

   //public static class IV {
   //   public static final int IV_SIZE = 0x10;

   //   byte iv[];

   //   public IV(byte iv[]) {
   //      this.iv = new byte[IV_SIZE];

   //      System.arraycopy(iv, 0, this.iv, 0, iv.length);
   //   }

   //   public byte[] data() {
   //      return iv;
   //   }
   //}

   //public static class SliceInfo {
   //   short clear_data_len;
   //   int encrypted_data_len;

   //   public SliceInfo(short clear_data_len, int encrypted_data_len) {
   //      this.clear_data_len = clear_data_len;
   //      this.encrypted_data_len = encrypted_data_len;
   //   }

   //   public short clear_data_len() {
   //      return clear_data_len;
   //   }

   //   public int encrypted_data_len() {
   //      return encrypted_data_len;
   //   }
   //}

   //public static class IV_2 extends IV {
   //   Vector < SliceInfo > slices;

   //   public IV_2(byte iv[]) {
   //      super(iv);

   //      slices = new Vector < SliceInfo > ();
   //   }

   //   public int slice_cnt() {
   //      return slices.size();
   //   }

   //   public SliceInfo get_slice(int idx) {
   //      if (idx < slice_cnt()) return slices.elementAt(idx);

   //      return null;
   //   }

   //   public void add_slice(SliceInfo si) {
   //      slices.add(si);
   //   }

   //   public int slice_len() {
   //      int len = 0;

   //      for (int i = 0; i < slice_cnt(); i++) {
   //         SliceInfo si = get_slice(i);

   //         len += si.clear_data_len();
   //         len += si.encrypted_data_len();
   //      }

   //      return len;
   //   }
   //}

   //public static class SampleEncryptionBox extends UUID {
   //   public static final String SEB_UUID = "a2394f525a9b4f14a2446c427c648df4";

   //   int flags;
   //   int sample_cnt;
   //   Vector < IV > ivs;

   //   public int sample_cnt() {
   //      return sample_cnt;
   //   }

   //   public static boolean uuid_match(byte uuid[]) {
   //      byte seb_uuid[] = Utils.parse_hex_string(SEB_UUID);

   //      for (int i = 0; i < UUID_SIZE; i++) {
   //         if (seb_uuid[i] != uuid[i]) return false;
   //      }

   //      return true;
   //   }

   //   public Vector < IV > parse_simple_ivs(ByteInput bi) {
   //      Vector < IV > ivs = new Vector < IV > ();

   //      sample_cnt = bi.read_4();

   //      for (int i = 0; i < sample_cnt; i++) {
   //         byte iv_data[] = bi.read_n(8);

   //         IV iv = new IV(iv_data);
   //         ivs.add(iv);
   //      }

   //      return ivs;
   //   }

   //   public Vector < IV > parse_nonstandard_ivs(ByteInput bi) {
   //      Vector < IV > ivs = new Vector < IV > ();

   //      sample_cnt = bi.read_4();

   //      for (int i = 0; i < sample_cnt; i++) {
   //         byte iv[] = bi.read_n(8);

   //         short seq_cnt = bi.read_2();

   //         IV_2 iv2 = new IV_2(iv);
   //         ivs.add(iv2);

   //         for (int j = 0; j < seq_cnt; j++) {
   //            short BytesOfClearData = bi.read_2();
   //            int BytesOfEncryptedData = bi.read_4();

   //            SliceInfo si = new SliceInfo(BytesOfClearData, BytesOfEncryptedData);
   //            iv2.add_slice(si);
   //         }
   //      }

   //      return ivs;
   //   }

   //   public SampleEncryptionBox(MP4File mp4, Box parent, int len, int type, byte data[]) {
   //      super(mp4, parent, "SampleEncryptionBox", len, type, data);

   //      ByteInput bi = new ByteInput(user_data);

   //      flags = bi.read_4();

   //      if (flags == 0) {
   //         ivs = parse_simple_ivs(bi);
   //      } else

   //      if (flags == 2) {
   //         ivs = parse_nonstandard_ivs(bi);
   //      } else ERR.log("Unexpected flags value in SampleEncryptionBox: " + Utils.hex_value(flags, 8));
   //   }

   //   public int iv_cnt() {
   //      return ivs.size();
   //   }

   //   public IV get_iv(int idx) {
   //      if (idx < ivs.size()) return ivs.elementAt(idx);
   //      else return null;
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");
   //         pp.println("flags:      " + Utils.hex_value(flags, 8));
   //         pp.println("sample_cnt: " + Utils.hex_value(sample_cnt, 8));

   //         pp.pad(2, "");
   //         for (int i = 0; i < ivs.size(); i++) {
   //            IV iv = get_iv(i);

   //            pp.printhex("IV " + Utils.hex_value(i, 4), iv.data());
   //         }
   //         pp.leave();

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class FTYP extends Box {
   //   int major_brand;
   //   int minor_version;
   //   int compatible_brands[];

   //   public FTYP(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, FTYP_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      major_brand = bi.read_4();
   //      minor_version = bi.read_4();

   //      int cnt = bi.remaining() >> 2;

   //      compatible_brands = new int[cnt];

   //      for (int i = 0; i < cnt; i++) {
   //         compatible_brands[i] = bi.read_4();
   //      }
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new FTYP(mp4, parent, data);
   //   }

   //   public FTYP(int major_brand, int minor_version, int compatible_brands[]) {
   //      super(FTYP_BOX);

   //      this.major_brand = major_brand;
   //      this.minor_version = minor_version;
   //      this.compatible_brands = compatible_brands;
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_4(major_brand);
   //      bo.write_4(minor_version);

   //      for (int i = 0; i < compatible_brands.length; i++) {
   //         bo.write_4(compatible_brands[i]);
   //      }
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");
   //         pp.println("major_brand:   " + int2str(major_brand));
   //         pp.println("minor_version: " + minor_version);
   //         pp.println("compatible_brands:");

   //         for (int i = 0; i < compatible_brands.length; i++) {
   //            pp.pad(2, "");
   //            pp.println(int2str(compatible_brands[i]));
   //            pp.leave();
   //         }

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class MVHD extends Box {
   //   byte version;
   //   long creation_time;
   //   long modification_time;
   //   int timescale;
   //   long duration;
   //   int rate;
   //   short volume;
   //   int unity_matrix[];
   //   int next_track_id;

   //   public MVHD(byte version, long creation_time, long modification_time, int timescale,
   //      long duration, int rate, short volume, int unity_matrix[], int next_track_id) {
   //      super(MVHD_BOX);

   //      this.version = version;
   //      this.creation_time = creation_time;
   //      this.modification_time = modification_time;
   //      this.timescale = timescale;
   //      this.duration = duration;
   //      this.rate = rate;
   //      this.volume = volume;
   //      this.unity_matrix = unity_matrix;
   //      this.next_track_id = next_track_id;
   //   }

   //   public MVHD(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, MVHD_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      version = bi.read_1();
   //      if (version != 1) ERR.log("Unexcpected MVHD version: " + version);

   //      //skip flags
   //      bi.skip(3);

   //      creation_time = bi.read_8();
   //      modification_time = bi.read_8();
   //      timescale = bi.read_4();
   //      duration = bi.read_8();

   //      rate = bi.read_4();
   //      volume = bi.read_2();

   //      //skip reserved
   //      bi.skip(2);

   //      //skip reserved again
   //      bi.skip(2 * 4);

   //      //read unity matrix
   //      unity_matrix = new int[9];
   //      for (int i = 0; i < unity_matrix.length; i++) {
   //         unity_matrix[i] = bi.read_4();
   //      }

   //      //skip predefined
   //      bi.skip(6 * 4);

   //      next_track_id = bi.read_4();
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new MVHD(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_1(version);

   //      //flags
   //      bo.write_zero(3);

   //      bo.write_8(creation_time);
   //      bo.write_8(modification_time);
   //      bo.write_4(timescale);
   //      bo.write_8(duration);

   //      bo.write_4(rate);
   //      bo.write_2(volume);

   //      //reserved
   //      bo.write_zero(2 + 2 * 4);

   //      for (int i = 0; i < unity_matrix.length; i++) {
   //         bo.write_4(unity_matrix[i]);
   //      }

   //      //predefined
   //      bo.write_zero(6 * 4);

   //      bo.write_4(next_track_id);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         pp.println("version:           " + Utils.hex_value(version, 8));
   //         pp.println("creation_time;:    " + Utils.hex_value(creation_time, 16) + " [" + Utils.long2date(creation_time) + "]");
   //         pp.println("modification_time: " + Utils.hex_value(modification_time, 16) + " [" + Utils.long2date(modification_time) + "]");
   //         pp.println("timescale:         " + Utils.hex_value(timescale, 16) + " [" + timescale + "]");
   //         pp.println("duration:          " + Utils.hex_value(duration, 16) + " [" + duration_str(duration / (long) timescale) + "]");
   //         pp.println("rate:              " + Utils.hex_value(rate, 8));
   //         pp.println("volume:            " + Utils.hex_value(volume, 4));

   //         pp.println("unity_matrix");
   //         pp.pad(2);
   //         for (int i = 0; i < unity_matrix.length; i++) {
   //            pp.println(Utils.hex_value(unity_matrix[i], 8));
   //         }
   //         pp.leave();

   //         pp.println("next_track_id:     " + Utils.hex_value(next_track_id, 8));

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class TKHD extends Box {
   //   byte version;
   //   int flags;
   //   long creation_time;
   //   long modification_time;
   //   int track_id;
   //   long duration;
   //   short layer;
   //   short alternate_group;
   //   short volume;
   //   int matrix[];
   //   int width;
   //   int height;

   //   public TKHD(byte version, int flags, long creation_time, long modification_time, int track_id, long duration, short layer, short alternate_group, short volume, int matrix[], int width, int height) {
   //      super(TKHD_BOX);

   //      this.version = version;
   //      this.flags = flags;
   //      this.creation_time = creation_time;
   //      this.modification_time = modification_time;
   //      this.track_id = track_id;
   //      this.duration = duration;
   //      this.layer = layer;
   //      this.alternate_group = alternate_group;
   //      this.volume = volume;
   //      this.matrix = matrix;
   //      this.width = width;
   //      this.height = height;
   //   }

   //   public TKHD(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, TKHD_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      version = bi.read_1();
   //      if (version != 1) ERR.log("Unexpected TKHD version: " + version);

   //      //skip flags
   //      flags = bi.read_3();

   //      creation_time = bi.read_8();
   //      modification_time = bi.read_8();
   //      track_id = bi.read_4();

   //      //skip reserved
   //      bi.skip(4);

   //      duration = bi.read_8();

   //      //skip reserved again
   //      bi.skip(2 * 4);

   //      layer = bi.read_2();
   //      alternate_group = bi.read_2();
   //      volume = bi.read_2();

   //      //skip reserved again
   //      bi.skip(2);

   //      //read matrix
   //      matrix = new int[9];
   //      for (int i = 0; i < matrix.length; i++) {
   //         matrix[i] = bi.read_4();
   //      }

   //      width = bi.read_4();
   //      height = bi.read_4();
   //   }

   //   public int track_id() {
   //      return track_id;
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new TKHD(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_1(version);

   //      //flags
   //      bo.write_3(flags);

   //      bo.write_8(creation_time);
   //      bo.write_8(modification_time);
   //      bo.write_4(track_id);

   //      //reserved
   //      bo.write_zero(4);

   //      bo.write_8(duration);

   //      //reserved
   //      bo.write_zero(2 * 4);

   //      bo.write_2(layer);
   //      bo.write_2(alternate_group);
   //      bo.write_2(volume);

   //      //reserved
   //      bo.write_zero(2);

   //      for (int i = 0; i < matrix.length; i++) {
   //         bo.write_4(matrix[i]);
   //      }

   //      bo.write_4(width);
   //      bo.write_4(height);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         pp.println("version:           " + Utils.hex_value(version, 8));
   //         pp.println("flags:             " + Utils.hex_value(flags, 8));
   //         pp.println("creation_time;:    " + Utils.hex_value(creation_time, 16));
   //         pp.println("modification_time: " + Utils.hex_value(modification_time, 16));
   //         pp.println("track_id:          " + Utils.hex_value(track_id, 8));
   //         pp.println("duration:          " + Utils.hex_value(duration, 16));
   //         pp.println("layer:             " + Utils.hex_value(layer, 4));
   //         pp.println("alternate_group:   " + Utils.hex_value(alternate_group, 4));
   //         pp.println("volume:            " + Utils.hex_value(volume, 4));

   //         pp.println("matrix");
   //         pp.pad(2);
   //         for (int i = 0; i < matrix.length; i++) {
   //            pp.println(Utils.hex_value(matrix[i], 8));
   //         }
   //         pp.leave();

   //         pp.println("width:             " + Utils.hex_value(width, 8) + " [" + (width >> 16) + "]");
   //         pp.println("height:            " + Utils.hex_value(height, 8) + " [" + (height >> 16) + "]");

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class MDHD extends Box {
   //   byte version;
   //   long creation_time;
   //   long modification_time;
   //   int timescale;
   //   long duration;
   //   short language;

   //   public MDHD(byte version, long creation_time, long modification_time, int timescale, long duration, short language) {
   //      super(MDHD_BOX);

   //      this.version = version;
   //      this.creation_time = creation_time;
   //      this.modification_time = modification_time;
   //      this.timescale = timescale;
   //      this.duration = duration;
   //      this.language = language;
   //   }

   //   public MDHD(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, MDHD_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      version = bi.read_1();
   //      if (version != 1) ERR.log("Unexpected TKHD version: " + version);

   //      //skip flags
   //      bi.skip(3);

   //      creation_time = bi.read_8();
   //      modification_time = bi.read_8();
   //      timescale = bi.read_4();

   //      duration = bi.read_8();

   //      language = bi.read_2();
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new MDHD(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_1(version);

   //      //flags
   //      bo.write_zero(3);

   //      bo.write_8(creation_time);
   //      bo.write_8(modification_time);
   //      bo.write_4(timescale);

   //      bo.write_8(duration);

   //      bo.write_2(language);

   //      //pre_defined
   //      bo.write_zero(2);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         pp.println("version:           " + Utils.hex_value(version, 8));
   //         pp.println("creation_time;:    " + Utils.hex_value(creation_time, 16));
   //         pp.println("modification_time: " + Utils.hex_value(modification_time, 16));
   //         pp.println("timescale:         " + Utils.hex_value(timescale, 8));
   //         pp.println("duration:          " + Utils.hex_value(duration, 16));
   //         pp.println("language:          " + Utils.hex_value(language, 4));

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class HDLR extends Box {
   //   int handler_type;
   //   String handler_name;

   //   public HDLR(int handler_type, String handler_name) {
   //      super(HDLR_BOX);

   //      this.handler_type = handler_type;
   //      this.handler_name = handler_name;
   //   }

   //   public HDLR(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, HDLR_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      //skip version and pre_defied fields
   //      bi.skip(8);

   //      handler_type = bi.read_4();

   //      //skip reserved
   //      bi.skip(3 * 4);

   //      handler_name = bi.read_string(bi.remaining() - 1);
   //   }

   //   public int handler_type() {
   //      return handler_type;
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new HDLR(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      //version and pre defined fields
   //      bo.write_zero(8);

   //      bo.write_4(handler_type);

   //      //reserved
   //      bo.write_zero(3 * 4);

   //      bo.write_string(handler_name);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         pp.println("handler_type:  " + Utils.hex_value(handler_type, 8) + " [" + int2str(handler_type) + "]");
   //         pp.println("name:          " + handler_name);

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class SMHD extends Box {
   //   short balance;

   //   public SMHD(short balance) {
   //      super(SMHD_BOX);

   //      this.balance = balance;
   //   }

   //   public SMHD(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, SMHD_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      //skip version
   //      bi.skip(4);

   //      balance = bi.read_2();

   //      //skip reserved
   //      bi.skip(2);
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new SMHD(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_zero(4);

   //      bo.write_2(balance);

   //      //reserved
   //      bo.write_zero(2);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         pp.println("balance:  " + Utils.hex_value(balance, 4));

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class STTSEntry {
   //   int count;
   //   int delta;

   //   public STTSEntry(int count, int delta) {
   //      this.count = count;
   //      this.delta = delta;
   //   }

   //   public int count() {
   //      return count;
   //   }

   //   public int delta() {
   //      return delta;
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      if (verbose) {
   //         pp.pad(2, "");
   //         pp.println("count:  " + Utils.hex_value(count, 8));
   //         pp.println("delta:  " + Utils.hex_value(delta, 8));
   //         pp.leave();
   //      }
   //   }
   //}

   //public static class STTS extends Box {
   //   int entry_count;
   //   STTSEntry table[];

   //   public STTS() {
   //      super(STTS_BOX);

   //      this.table = new STTSEntry[0];
   //      this.entry_count = 0;
   //   }

   //   public STTS(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, STTS_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      //skip version
   //      bi.skip(4);

   //      entry_count = bi.read_4();

   //      table = new STTSEntry[entry_count];

   //      for (int i = 0; i < entry_count; i++) {
   //         int sample_count = bi.read_4();
   //         int sample_delta = bi.read_4();

   //         table[i] = new STTSEntry(sample_count, sample_delta);
   //      }
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new STTS(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_zero(4);

   //      bo.write_4(entry_count);

   //      for (int i = 0; i < entry_count; i++) {
   //         STTSEntry entry = table[i];

   //         bo.write_4(entry.count());
   //         bo.write_4(entry.delta());
   //      }
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         pp.println("entry_count:  " + Utils.hex_value(entry_count, 4));

   //         for (int i = 0; i < entry_count; i++) {
   //            pp.println("entry " + i);
   //            STTSEntry stts = table[i];
   //            stts.print(verbose);
   //         }

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class CTTSEntry {
   //   int count;
   //   int offset;

   //   public CTTSEntry(int count, int offset) {
   //      this.count = count;
   //      this.offset = offset;
   //   }

   //   public int count() {
   //      return count;
   //   }

   //   public int offset() {
   //      return offset;
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      if (verbose) {
   //         pp.pad(2, "");
   //         pp.println("count:  " + Utils.hex_value(count, 8));
   //         pp.println("offset: " + Utils.hex_value(offset, 8));
   //         pp.leave();
   //      }
   //   }
   //}

   //public static class CTTS extends Box {
   //   int entry_count;
   //   CTTSEntry table[];

   //   public CTTS() {
   //      super(CTTS_BOX);

   //      this.table = new CTTSEntry[0];
   //      this.entry_count = 0;
   //   }

   //   public CTTS(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, CTTS_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      //skip version
   //      bi.skip(4);

   //      entry_count = bi.read_4();

   //      table = new CTTSEntry[entry_count];

   //      for (int i = 0; i < entry_count; i++) {
   //         int sample_count = bi.read_4();
   //         int sample_offset = bi.read_4();

   //         table[i] = new CTTSEntry(sample_count, sample_offset);
   //      }
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new CTTS(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_zero(4);

   //      bo.write_4(entry_count);

   //      for (int i = 0; i < entry_count; i++) {
   //         CTTSEntry entry = table[i];

   //         bo.write_4(entry.count());
   //         bo.write_4(entry.offset());
   //      }
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         pp.println("entry_count:  " + Utils.hex_value(entry_count, 4));

   //         for (int i = 0; i < entry_count; i++) {
   //            pp.println("entry " + i);
   //            CTTSEntry ctts = table[i];
   //            ctts.print(verbose);
   //         }

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class STSCEntry {
   //   int first_chunk;
   //   int samples_per_chunk;
   //   int sample_desc_idx;

   //   public STSCEntry(int first_chunk, int samples_per_chunk, int sample_desc_idx) {
   //      this.first_chunk = first_chunk;
   //      this.samples_per_chunk = samples_per_chunk;
   //      this.sample_desc_idx = sample_desc_idx;
   //   }

   //   public int first_chunk() {
   //      return first_chunk;
   //   }

   //   public int samples_per_chunk() {
   //      return samples_per_chunk;
   //   }

   //   public int sample_desc_idx() {
   //      return sample_desc_idx;
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      if (verbose) {
   //         pp.pad(2, "");
   //         pp.println("first_chunk:       " + Utils.hex_value(first_chunk, 8));
   //         pp.println("samples_per_chunk: " + Utils.hex_value(samples_per_chunk, 8));
   //         pp.println("sample_desc_idx:   " + Utils.hex_value(sample_desc_idx, 8));
   //         pp.leave();
   //      }
   //   }
   //}

   //public static class STSC extends Box {
   //   int entry_count;
   //   STSCEntry table[];

   //   public STSC() {
   //      super(STSC_BOX);

   //      this.table = new STSCEntry[0];
   //      this.entry_count = 0;
   //   }

   //   public STSC(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, STSC_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      //skip version
   //      bi.skip(4);

   //      entry_count = bi.read_4();

   //      table = new STSCEntry[entry_count];

   //      for (int i = 0; i < entry_count; i++) {
   //         int first_chunk = bi.read_4();
   //         int samples_per_chunk = bi.read_4();
   //         int sample_desc_idx = bi.read_4();

   //         table[i] = new STSCEntry(first_chunk, samples_per_chunk, sample_desc_idx);
   //      }
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new STSC(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_zero(4);

   //      bo.write_4(entry_count);

   //      for (int i = 0; i < entry_count; i++) {
   //         STSCEntry entry = table[i];
   //         bo.write_4(entry.first_chunk());
   //         bo.write_4(entry.samples_per_chunk());
   //         bo.write_4(entry.sample_desc_idx());
   //      }
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         pp.println("entry_count:  " + Utils.hex_value(entry_count, 4));

   //         for (int i = 0; i < entry_count; i++) {
   //            pp.println("entry " + i);
   //            STSCEntry stsc = table[i];
   //            stsc.print(verbose);
   //         }

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class STSZ extends Box {
   //   int sample_size;
   //   int sample_count;
   //   int sizes[];

   //   public STSZ() {
   //      super(STSZ_BOX);

   //      this.sample_size = 0;
   //      this.sizes = new int[0];
   //      this.sample_count = 0;
   //   }

   //   public STSZ(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, STSZ_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      //skip version
   //      bi.skip(4);

   //      sample_size = bi.read_4();
   //      sample_count = bi.read_4();

   //      if (sample_size == 0) {
   //         sizes = new int[sample_count];

   //         for (int i = 0; i < sample_count; i++) {
   //            sizes[i] = bi.read_4();
   //         }
   //      }
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new STSZ(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_zero(4);

   //      bo.write_4(sample_size);
   //      bo.write_4(sample_count);

   //      if (sample_size == 0) {
   //         for (int i = 0; i < sizes.length; i++) {
   //            bo.write_4(sizes[i]);
   //         }
   //      }
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         pp.println("sample_size:  " + Utils.hex_value(sample_size, 4));
   //         pp.println("sample_count: " + Utils.hex_value(sample_count, 4));

   //         for (int i = 0; i < sample_count; i++) {
   //            int size = sizes[i];
   //            pp.println("size " + Utils.hex_value(size, 4));
   //         }

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class STCO extends Box {
   //   int entry_count;
   //   int chunk_offsets[];

   //   public STCO() {
   //      super(STCO_BOX);

   //      this.chunk_offsets = new int[0];
   //      this.entry_count = 0;
   //   }

   //   public STCO(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, STCO_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      //skip version
   //      bi.skip(4);

   //      entry_count = bi.read_4();

   //      chunk_offsets = new int[entry_count];

   //      for (int i = 0; i < entry_count; i++) {
   //         chunk_offsets[i] = bi.read_4();
   //      }
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new STCO(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_zero(4);

   //      bo.write_4(entry_count);

   //      for (int i = 0; i < entry_count; i++) {
   //         bo.write_4(chunk_offsets[i]);
   //      }
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         pp.println("entry_count: " + Utils.hex_value(entry_count, 4));

   //         for (int i = 0; i < entry_count; i++) {
   //            int chunk_offset = chunk_offsets[i];
   //            pp.println("chunk_offset " + Utils.hex_value(chunk_offset, 4));
   //         }

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class URL extends Box {
   //   int entry_flags;
   //   String location;

   //   public URL(String location) {
   //      super(URL_BOX);

   //      if (location.equals("")) {
   //         this.entry_flags = 1;
   //      }

   //      this.location = location;
   //   }

   //   public URL(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, URL_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      //skip version
   //      entry_flags = bi.read_4();

   //      if (entry_flags != 1) {
   //         location = bi.read_string(bi.remaining());
   //      } else {
   //         location = "";
   //      }
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new URL(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_4(entry_flags);

   //      if (entry_flags != 1) {
   //         bo.write_string(location);
   //      }
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");
   //         pp.println("entry_flags: " + entry_flags);
   //         pp.println("location:    " + location);
   //         pp.leave();
   //      }
   //   }
   //}

   //public static class DREF extends Box {
   //   int entry_count;
   //   Box detable[];

   //   public DREF(Box detable[]) {
   //      super(DREF_BOX);

   //      this.detable = detable;
   //      entry_count = detable.length;
   //   }

   //   public DREF(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, DREF_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      //skip version
   //      bi.skip(4);

   //      entry_count = bi.read_4();

   //      detable = new Box[entry_count];

   //      Vector < Box > boxes = read_boxes(bi.remaining_data());

   //      if (boxes.size() != entry_count) ERR.log("Inconsistent count of DREF entries");

   //      for (int i = 0; i < entry_count; i++) {
   //         detable[i] = Box.parse(mp4, this, boxes.elementAt(i));
   //      }
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new DREF(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_zero(4);

   //      bo.write_4(entry_count);

   //      for (int i = 0; i < entry_count; i++) {
   //         detable[i].write(bo);
   //      }
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         for (int i = 0; i < entry_count; i++) {
   //            Box de = detable[i];
   //            de.print(verbose);
   //         }

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class MEHD extends Box {
   //   byte version;
   //   long fragment_duration;

   //   public MEHD(byte version, long fragment_duration) {
   //      super(MEHD_BOX);

   //      this.version = version;
   //      this.fragment_duration = fragment_duration;
   //   }

   //   public MEHD(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, MEHD_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      version = bi.read_1();
   //      if (version != 1) ERR.log("Unexpected MEHD version: " + version);

   //      //skip flags
   //      bi.skip(3);

   //      fragment_duration = bi.read_8();
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new MEHD(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_1(version);

   //      bo.write_zero(3);

   //      bo.write_8(fragment_duration);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         pp.println("fragment_duration:    " + Utils.hex_value(fragment_duration, 16));

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class TREX extends Box {
   //   int track_ID;
   //   int default_sample_description_index;
   //   int default_sample_duration;
   //   int default_sample_size;
   //   int default_sample_flags;

   //   public TREX(int track_ID, int default_sample_description_index, int default_sample_duration, int default_sample_size, int default_sample_flags) {
   //      super(TREX_BOX);

   //      this.track_ID = track_ID;
   //      this.default_sample_description_index = default_sample_description_index;
   //      this.default_sample_duration = default_sample_duration;
   //      this.default_sample_size = default_sample_size;
   //      this.default_sample_flags = default_sample_flags;
   //   }

   //   public TREX(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, TREX_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      //skip version
   //      bi.skip(4);

   //      track_ID = bi.read_4();
   //      default_sample_description_index = bi.read_4();
   //      default_sample_duration = bi.read_4();
   //      default_sample_size = bi.read_4();
   //      default_sample_flags = bi.read_4();
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new TREX(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_zero(4);

   //      bo.write_4(track_ID);
   //      bo.write_4(default_sample_description_index);
   //      bo.write_4(default_sample_duration);
   //      bo.write_4(default_sample_size);
   //      bo.write_4(default_sample_flags);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");
   //         pp.println("track_ID:                         " + Utils.hex_value(track_ID, 8));
   //         pp.println("default_sample_description_index: " + Utils.hex_value(default_sample_description_index, 8));
   //         pp.println("default_sample_duration:          " + Utils.hex_value(default_sample_duration, 8));
   //         pp.println("default_sample_size:              " + Utils.hex_value(default_sample_size, 8));
   //         pp.println("default_sample_flags:             " + Utils.hex_value(default_sample_flags, 8));
   //         pp.leave();
   //      }
   //   }
   //}

   //public static class TFHD extends Box {
   //   public static final int BASED_DATA_OFFSET_PRESENT = 0x000001;
   //   public static final int SAMPLE_DESCRIPTION_INDEX_PRESENT = 0x000002;
   //   public static final int DEFAULT_SAMPLE_DURATION_PRESENT = 0x000008;
   //   public static final int DEFAULT_SAMPLE_SIZE_PRESENT = 0x000010;
   //   public static final int DEFAULT_SAMPLE_FLAGS_PRESENT = 0x000020;

   //   int tr_flags;
   //   int track_ID;
   //   long base_data_offset;
   //   int sample_description_index;
   //   int default_sample_duration;
   //   int default_sample_size;
   //   int default_sample_flags;

   //   public boolean flag(int val) {
   //      if ((tr_flags & val) == val) return true;
   //      else return false;
   //   }

   //   public TFHD(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, TFHD_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      tr_flags = bi.read_4();

   //      track_ID = bi.read_4();

   //      if (flag(BASED_DATA_OFFSET_PRESENT)) base_data_offset = bi.read_8();
   //      if (flag(SAMPLE_DESCRIPTION_INDEX_PRESENT)) sample_description_index = bi.read_4();
   //      if (flag(DEFAULT_SAMPLE_DURATION_PRESENT)) default_sample_duration = bi.read_4();
   //      if (flag(DEFAULT_SAMPLE_SIZE_PRESENT)) default_sample_size = bi.read_4();
   //      if (flag(DEFAULT_SAMPLE_FLAGS_PRESENT)) default_sample_flags = bi.read_4();
   //   }

   //   public int trackid() {
   //      return track_ID;
   //   }

   //   public void set_trackid(int trackid) {
   //      track_ID = trackid;
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new TFHD(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_4(tr_flags);

   //      bo.write_4(track_ID);

   //      if (flag(BASED_DATA_OFFSET_PRESENT)) bo.write_8(base_data_offset);
   //      if (flag(SAMPLE_DESCRIPTION_INDEX_PRESENT)) bo.write_4(sample_description_index);
   //      if (flag(DEFAULT_SAMPLE_DURATION_PRESENT)) bo.write_4(default_sample_duration);
   //      if (flag(DEFAULT_SAMPLE_SIZE_PRESENT)) bo.write_4(default_sample_size);
   //      if (flag(DEFAULT_SAMPLE_FLAGS_PRESENT)) bo.write_4(default_sample_flags);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");
   //         pp.println("track_ID:                         " + Utils.hex_value(track_ID, 8));

   //         if (flag(BASED_DATA_OFFSET_PRESENT)) pp.println("base_data_offset:         " + Utils.hex_value(base_data_offset, 16));
   //         if (flag(SAMPLE_DESCRIPTION_INDEX_PRESENT)) pp.println("sample_description_index: " + Utils.hex_value(sample_description_index, 8));
   //         if (flag(DEFAULT_SAMPLE_DURATION_PRESENT)) pp.println("default_sample_duration:  " + Utils.hex_value(default_sample_duration, 8));
   //         if (flag(DEFAULT_SAMPLE_SIZE_PRESENT)) pp.println("default_sample_size:      " + Utils.hex_value(default_sample_size, 8));
   //         if (flag(DEFAULT_SAMPLE_FLAGS_PRESENT)) pp.println("default_sample_flags:     " + Utils.hex_value(default_sample_flags, 8));

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class ESDescriptor extends BaseDescriptor {
   //   short es_id;
   //   byte flags;
   //   byte priority;
   //   DecoderConfigDescr dcdesc;
   //   SLConfigDescriptor slcdesc;

   //   public ESDescriptor(short es_id, byte flags, byte priority, DecoderConfigDescr dcdesc, SLConfigDescriptor slcdesc) {
   //      super(ESDescrTag);

   //      this.es_id = es_id;
   //      this.flags = flags;
   //      this.priority = priority;
   //      this.dcdesc = dcdesc;
   //      this.slcdesc = slcdesc;
   //   }

   //   public ESDescriptor(byte tag, int len, byte data[]) {
   //      super(tag, len, data);

   //      ByteInput bi = new ByteInput(data);

   //      es_id = bi.read_2();
   //      byte b = bi.read_1();

   //      flags = (byte)(b & 0xe0);
   //      priority = (byte)(b & 0x1f);

   //      dcdesc = (DecoderConfigDescr) BaseDescriptor.read(bi);
   //      slcdesc = (SLConfigDescriptor) BaseDescriptor.read(bi);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_2(es_id);
   //      bo.write_1((byte)(flags | priority));

   //      dcdesc.write(bo);
   //      slcdesc.write(bo);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      if (verbose) {
   //         pp.println("tag: " + Utils.hex_value(tag(), 2) + " " + name());
   //         pp.println("len: " + Utils.hex_value(len(), 8));

   //         pp.pad(2, "");
   //         pp.println("es_id:    " + Utils.hex_value(es_id, 4));
   //         pp.println("flags:    " + Utils.hex_value(flags, 2));
   //         pp.println("priority: " + Utils.hex_value(priority, 2));

   //         dcdesc.print(verbose);
   //         slcdesc.print(verbose);
   //         pp.leave();
   //      }
   //   }
   //}

   //public static class DecoderConfigDescr extends BaseDescriptor {
   //   byte objectType;
   //   byte streamType;
   //   byte upStream;
   //   int bufferSizeDB;
   //   int maxBitrate;
   //   int avgBitrate;;
   //   DecoderSpecificInfo dsinfo;

   //   public String objectType_name(byte objectType) {
   //      switch (objectType) {
   //      case 0x66:
   //         return "MPEG2 AAC-Main Profile";
   //      case 0x67:
   //         return "MPEG2 AAC-Low Complexity Profile";
   //      case 0x68:
   //         return "MPEG2 AAC-Scaleable Sampling Rate Profile";
   //      }

   //      return "unknown";
   //   }

   //   public DecoderConfigDescr(byte objectType, byte streamType, byte upStream, int bufferSizeDB, int maxBitrate, int avgBitrate, DecoderSpecificInfo dsinfo) {
   //      super(DecoderConfigDescrTag);

   //      this.objectType = objectType;
   //      this.streamType = streamType;
   //      this.upStream = upStream;
   //      this.bufferSizeDB = bufferSizeDB;
   //      this.maxBitrate = maxBitrate;
   //      this.avgBitrate = avgBitrate;
   //      this.dsinfo = dsinfo;
   //   }

   //   public DecoderConfigDescr(byte tag, int len, byte data[]) {
   //      super(tag, len, data);

   //      ByteInput bi = new ByteInput(data);

   //      objectType = bi.read_1();
   //      byte b = bi.read_1();
   //      streamType = (byte)(b & 0xfd);
   //      upStream = (byte)(b & 0x02);
   //      bufferSizeDB = bi.read_3();
   //      maxBitrate = bi.read_4();
   //      avgBitrate = bi.read_4();

   //      if (bi.remaining() > 0) {
   //         dsinfo = (DecoderSpecificInfo) BaseDescriptor.read(bi);
   //      }
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_1(objectType);
   //      bo.write_1((byte)(streamType | upStream));
   //      bo.write_3(bufferSizeDB);
   //      bo.write_4(maxBitrate);
   //      bo.write_4(avgBitrate);

   //      if (dsinfo != null) {
   //         dsinfo.write(bo);
   //      }
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      if (verbose) {
   //         pp.println("tag: " + Utils.hex_value(tag(), 2) + " " + name());
   //         pp.println("len: " + Utils.hex_value(len(), 8));

   //         pp.pad(2, "");
   //         pp.println("objectType:   " + Utils.hex_value(objectType, 8) + " [" + objectType_name(objectType) + "]");
   //         pp.println("streamType:   " + Utils.hex_value(streamType, 8));
   //         pp.println("upStream:     " + Utils.hex_value(upStream, 8));
   //         pp.println("bufferSizeDB: " + Utils.hex_value(bufferSizeDB, 8));
   //         pp.println("maxBitrate:   " + Utils.hex_value(maxBitrate, 8));
   //         pp.println("avgBitrate:   " + Utils.hex_value(avgBitrate, 8));

   //         if (dsinfo != null) {
   //            dsinfo.print(verbose);
   //         }
   //         pp.leave();
   //      }
   //   }
   //}

   //public static class DecoderSpecificInfo extends BaseDescriptor {
   //   public DecoderSpecificInfo(byte data[]) {
   //      this(DecSpecificInfoTag, data.length, data);
   //   }

   //   public DecoderSpecificInfo(byte tag, int len, byte data[]) {
   //      super(tag, len, data);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      if (verbose) {
   //         pp.println("tag: " + Utils.hex_value(tag(), 2) + " " + name());
   //         pp.println("len: " + Utils.hex_value(len(), 8));

   //         pp.printhex("data", data);
   //      }
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_n(data);
   //   }
   //}

   //public static class SLConfigDescriptor extends BaseDescriptor {
   //   public SLConfigDescriptor(byte data[]) {
   //      this(SLConfigDescrTag, data.length, data);
   //   }

   //   public SLConfigDescriptor(byte tag, int len, byte data[]) {
   //      super(tag, len, data);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      if (verbose) {
   //         pp.println("tag: " + Utils.hex_value(tag(), 2) + " " + name());
   //         pp.println("len: " + Utils.hex_value(len(), 8));

   //         pp.printhex("data", data);
   //      }
   //   }

   //   //not sure about this - MS sample doesn't encode size as var len for SLConfigDescriptor
   //   public void write_size(ByteOutput bo, int len) {
   //      bo.write_1((byte) len);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_n(data);
   //   }
   //}

   //public static class BaseDescriptor {
   //   //supported descriptor tags
   //   public static final byte ESDescrTag = 0x03;
   //   public static final byte DecoderConfigDescrTag = 0x04;
   //   public static final byte DecSpecificInfoTag = 0x05;
   //   public static final byte SLConfigDescrTag = 0x06;

   //   byte tag;
   //   int len;
   //   byte data[];

   //   public static int read_varlen_size(ByteInput bi) {
   //      int size = 0;

   //      for (int i = 0; i < 4; i++) {
   //         int b = ((int) bi.read_1()) & 0xff;

   //         size = (size << 7) | (b & 0x7f);

   //         if ((b & 0x80) == 0) break;
   //      }

   //      return size;
   //   }

   //   public void write_varlen_size(ByteOutput bo, int size) {
   //      byte b1 = (byte)(size & 0x7f);
   //      byte b2 = (byte)((size >> 7) & 0x7f);
   //      byte b3 = (byte)((size >> 14) & 0x7f);
   //      byte b4 = (byte)((size >> 21) & 0x7f);

   //      if ((size >> 7) == 0) {
   //         //1 byte
   //         bo.write_1((byte) 0x80);
   //         bo.write_1((byte) 0x80);
   //         bo.write_1((byte) 0x80);

   //         bo.write_1(b1);
   //      } else

   //      if ((size >> 14) == 0) {
   //         //2 bytes
   //         bo.write_1((byte) 0x80);
   //         bo.write_1((byte) 0x80);

   //         bo.write_1((byte)(b2 | 0x80));
   //         bo.write_1(b1);
   //      } else

   //      if ((size >> 21) == 0) {
   //         //3 bytes
   //         bo.write_1((byte) 0x80);

   //         bo.write_1((byte)(b3 | 0x80));
   //         bo.write_1((byte)(b2 | 0x80));
   //         bo.write_1(b1);
   //      } else {
   //         //4 bytes
   //         bo.write_1((byte)(b4 | 0x80));
   //         bo.write_1((byte)(b3 | 0x80));
   //         bo.write_1((byte)(b2 | 0x80));
   //         bo.write_1(b1);
   //      }
   //   }

   //   public String name() {
   //      switch (tag) {
   //      case ESDescrTag:
   //         return "ESDescr";
   //      case DecoderConfigDescrTag:
   //         return "DecoderConfigDescr";
   //      case DecSpecificInfoTag:
   //         return "DecSpecificInfo";
   //      case SLConfigDescrTag:
   //         return "SLConfigDescr";
   //      }

   //      return null;
   //   }

   //   public BaseDescriptor(byte tag, int len, byte data[]) {
   //      this.tag = tag;
   //      this.len = len;;
   //      this.data = data;
   //   }

   //   public BaseDescriptor(byte tag) {
   //      this(tag, 0, null);
   //   }

   //   public byte tag() {
   //      return tag;
   //   }

   //   public int len() {
   //      return len;
   //   }

   //   public byte[] data() {
   //      return data;
   //   }

   //   public void write_size(ByteOutput bo, int len) {
   //      write_varlen_size(bo, len);
   //   }

   //   public void write(ByteOutput bo) {
   //      byte data[] = data();

   //      if (data != null) {
   //         bo.write_1(tag);
   //         write_size(bo, len);
   //         bo.write_n(data);
   //      } else {
   //         ByteOutput bos = new ByteOutput(BYTEOUTPUT_SIZE);
   //         write_data(bos);

   //         byte desc_data[] = bos.bytes();
   //         int desc_len = desc_data.length;

   //         bo.write_1(tag);
   //         write_size(bo, desc_len);
   //         bo.write_n(desc_data);
   //      }
   //   }

   //   public void write_data(ByteOutput bo) {
   //      ERR.log("unimplemented write for " + tag() + " Descriptor");
   //   }

   //   public static BaseDescriptor read(ByteInput bi) {
   //      byte tag = bi.read_1();

   //      int len = read_varlen_size(bi);

   //      byte data[] = bi.read_n(len);

   //      switch (tag) {
   //      case ESDescrTag:
   //         return new ESDescriptor(tag, len, data);
   //      case DecoderConfigDescrTag:
   //         return new DecoderConfigDescr(tag, len, data);
   //      case DecSpecificInfoTag:
   //         return new DecoderSpecificInfo(tag, len, data);
   //      case SLConfigDescrTag:
   //         return new SLConfigDescriptor(tag, len, data);
   //      }

   //      return new BaseDescriptor(tag, len, data);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      if (verbose) {
   //         pp.println("tag: " + Utils.hex_value(tag(), 2));
   //         pp.println("len: " + Utils.hex_value(len(), 8));
   //         pp.printhex("data", data());
   //      }
   //   }
   //}

   //public static class ESDS extends Box {
   //   Vector < BaseDescriptor > descriptors;

   //   public ESDS(Vector < BaseDescriptor > descriptors) {
   //      super(ESDS_BOX);

   //      this.descriptors = descriptors;
   //   }

   //   public ESDS(ESDescriptor esdesc) {
   //      super(ESDS_BOX);

   //      descriptors = new Vector < BaseDescriptor > ();
   //      descriptors.add(esdesc);
   //   }

   //   public ESDS(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, ESDS_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      //skip tag, length, version and flags
   //      bi.skip(12);

   //      descriptors = new Vector < BaseDescriptor > ();

   //      while (bi.remaining() > 0) {
   //         BaseDescriptor desc = BaseDescriptor.read(bi);
   //         descriptors.add(desc);
   //      }
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new ESDS(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_zero(4);

   //      for (int i = 0; i < descriptors.size(); i++) {
   //         BaseDescriptor desc = descriptors.elementAt(i);
   //         desc.write(bo);
   //      }
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         for (int i = 0; i < descriptors.size(); i++) {
   //            BaseDescriptor desc = descriptors.elementAt(i);
   //            desc.print(verbose);
   //         }

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class AVCC extends Box {
   //   byte config_version;
   //   byte AVCProfileIndication;
   //   byte profile_compatibility;
   //   byte AVCLevelIndication;
   //   byte lengthSizeMinusOne;
   //   byte numOfSequenceParameterSets;
   //   short sequenceParameterSetLength;
   //   byte sequenceParameterSetNALUnit[];
   //   byte numOfPictureParameterSets;
   //   short pictureParameterSetLength;;
   //   byte pictureParameterSetNALUnit[];

   //   public AVCC(byte config_version, byte AVCProfileIndication, byte profile_compatibility, byte AVCLevelIndication,
   //      byte lengthSizeMinusOne, byte sequenceParameterSetNALUnit[], byte pictureParameterSetNALUnit[]) {
   //      super(AVCC_BOX);

   //      this.config_version = config_version;
   //      this.AVCProfileIndication = AVCProfileIndication;
   //      this.profile_compatibility = profile_compatibility;
   //      this.AVCLevelIndication = AVCLevelIndication;
   //      this.lengthSizeMinusOne = 0x03;
   //      this.numOfSequenceParameterSets = 1;
   //      this.sequenceParameterSetLength = (short) sequenceParameterSetNALUnit.length;
   //      this.sequenceParameterSetNALUnit = sequenceParameterSetNALUnit;
   //      this.numOfPictureParameterSets = 1;
   //      this.pictureParameterSetLength = (short) pictureParameterSetNALUnit.length;
   //      this.pictureParameterSetNALUnit = pictureParameterSetNALUnit;
   //   }

   //   public AVCC(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, AVCC_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      //skip tag and length
   //      bi.skip(8);

   //      this.config_version = bi.read_1();
   //      this.AVCProfileIndication = bi.read_1();
   //      this.profile_compatibility = bi.read_1();
   //      this.AVCLevelIndication = bi.read_1();
   //      this.lengthSizeMinusOne = (byte)(bi.read_1() & 0x03);
   //      this.numOfSequenceParameterSets = (byte)(bi.read_1() & 0x1f);
   //      this.sequenceParameterSetLength = bi.read_2();
   //      this.sequenceParameterSetNALUnit = bi.read_n(sequenceParameterSetLength);
   //      this.numOfPictureParameterSets = bi.read_1();
   //      this.pictureParameterSetLength = bi.read_2();
   //      this.pictureParameterSetNALUnit = bi.read_n(pictureParameterSetLength);
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new AVCC(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_1(config_version);
   //      bo.write_1(AVCProfileIndication);
   //      bo.write_1(profile_compatibility);
   //      bo.write_1(AVCLevelIndication);

   //      byte b = (byte)(0xfc | (lengthSizeMinusOne & 0x03));
   //      bo.write_1(b);

   //      b = (byte)(0xe0 | (numOfSequenceParameterSets & 0x1f));
   //      bo.write_1(b);

   //      bo.write_2(sequenceParameterSetLength);
   //      bo.write_n(sequenceParameterSetNALUnit);

   //      bo.write_1(numOfPictureParameterSets);
   //      bo.write_2(pictureParameterSetLength);
   //      bo.write_n(pictureParameterSetNALUnit);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         pp.println("config_version: " + Utils.hex_value(config_version, 2));
   //         pp.println("AVCProfileIndication: " + Utils.hex_value(AVCProfileIndication, 2));
   //         pp.println("profile_compatibility: " + Utils.hex_value(profile_compatibility, 2));
   //         pp.println("AVCLevelIndication: " + Utils.hex_value(AVCLevelIndication, 2));
   //         pp.println("lengthSizeMinusOne: " + Utils.hex_value(lengthSizeMinusOne, 2));

   //         pp.println("numOfSequenceParameterSets: " + Utils.hex_value(numOfSequenceParameterSets, 2));
   //         pp.printhex("sequenceParameterSetNALUnit", sequenceParameterSetNALUnit);

   //         pp.println("numOfPictureParameterSets: " + Utils.hex_value(numOfPictureParameterSets, 4));
   //         pp.printhex("pictureParameterSetNALUnit", pictureParameterSetNALUnit);

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class MP4A extends Box {
   //   short data_reference_index;
   //   short channel_count;
   //   short sample_size;
   //   int sample_rate;
   //   ESDS esds;

   //   public MP4A(short data_reference_index, short channel_count, short sample_size, int sample_rate, ESDS esds) {
   //      super(MP4A_BOX);

   //      this.data_reference_index = data_reference_index;
   //      this.channel_count = channel_count;
   //      this.sample_size = sample_size;
   //      this.sample_rate = sample_rate;
   //      this.esds = esds;
   //   }

   //   public MP4A(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, MP4A_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      //skip tag and length
   //      bi.skip(8);

   //      //skip reserved
   //      bi.skip(6);

   //      data_reference_index = bi.read_2();

   //      //skip pre_defined and reserverd
   //      bi.skip(8);

   //      channel_count = bi.read_2();
   //      sample_size = bi.read_2();

   //      //skip pre_defined and reserved
   //      bi.skip(4);

   //      sample_rate = bi.read_4();

   //      esds = (ESDS) ESDS.get(mp4, parent, bi.remaining_data());
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new MP4A(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      //reserved
   //      bo.write_zero(6);

   //      bo.write_2(data_reference_index);

   //      //reserved
   //      bo.write_zero(8);

   //      bo.write_2(channel_count);
   //      bo.write_2(sample_size);

   //      //pre_defined and reserved
   //      bo.write_zero(4);

   //      bo.write_4(sample_rate);

   //      esds.write(bo);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         pp.println("data_reference_index: " + Utils.hex_value(data_reference_index, 4));
   //         pp.println("channel_count:        " + Utils.hex_value(channel_count, 4));
   //         pp.println("sample_size:          " + Utils.hex_value(sample_size, 4));
   //         pp.println("sample_rate:          " + Utils.hex_value(sample_rate, 8) + " [" + ((sample_rate >> 16) & 0xffff) + "]");

   //         esds.print(verbose);

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class AudioSampleEntry extends SampleEntry {
   //   MP4A mp4a;

   //   public AudioSampleEntry(MP4A mp4a) {
   //      this.mp4a = mp4a;
   //   }

   //   public AudioSampleEntry(MP4File mp4, Box parent, byte data[]) {
   //      mp4a = (MP4A) Box.parse(mp4, parent, MP4A.get(mp4, parent, data));
   //   }

   //   public void write(ByteOutput bo) {
   //      mp4a.write(bo);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      if (verbose) {
   //         mp4a.print(verbose);
   //      }
   //   }
   //}

   //public static class AVC1 extends Box {
   //   short data_reference_index;
   //   short width;
   //   short height;
   //   int horizontal_res;
   //   int vertical_res;
   //   short frame_count;
   //   short depth;
   //   AVCC avcc;

   //   public AVC1(short data_reference_index, short width, short height, AVCC avcc) {
   //      super(AVC1_BOX);

   //      this.data_reference_index = data_reference_index;
   //      this.width = width;
   //      this.height = height;

   //      int res = 72;
   //      this.horizontal_res = res << 16;
   //      this.vertical_res = res << 16;

   //      this.frame_count = 1;
   //      this.depth = 24;

   //      this.avcc = avcc;
   //   }

   //   public AVC1(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, AVC1_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      //skip tag and length
   //      bi.skip(8);

   //      //skip reserved
   //      bi.skip(6);

   //      data_reference_index = bi.read_2();

   //      //skip pre_defined and reserverd
   //      bi.skip(0x10);

   //      width = bi.read_2();
   //      height = bi.read_2();

   //      horizontal_res = bi.read_4();
   //      vertical_res = bi.read_4();

   //      //skip reserved
   //      bi.skip(4);

   //      frame_count = bi.read_2();

   //      //skip compressorname
   //      bi.skip(0x20);

   //      depth = bi.read_2();

   //      //skip pre_defined
   //      bi.skip(2);

   //      avcc = (AVCC) AVCC.get(mp4, parent, bi.remaining_data());
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new AVC1(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      //reserved
   //      bo.write_zero(6);

   //      bo.write_2(data_reference_index);

   //      //pre_defined and reserved
   //      bo.write_zero(0x10);

   //      bo.write_2(width);
   //      bo.write_2(height);

   //      bo.write_4(horizontal_res);
   //      bo.write_4(vertical_res);

   //      //reserved
   //      bo.write_zero(4);

   //      bo.write_2(frame_count);

   //      //compressorname
   //      bo.write_zero(0x20);

   //      bo.write_2(depth);

   //      //pre_defined
   //      bo.write_2((short) 0xffff);

   //      avcc.write(bo);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         pp.println("data_reference_index: " + Utils.hex_value(data_reference_index, 4));
   //         pp.println("width:           " + Utils.hex_value(width, 4));
   //         pp.println("height:          " + Utils.hex_value(height, 4));
   //         pp.println("horizontal_res:  " + Utils.hex_value(horizontal_res, 8) + " [" + ((horizontal_res >> 16) & 0xffff) + "]");
   //         pp.println("vertical_res:    " + Utils.hex_value(vertical_res, 8) + " [" + ((vertical_res >> 16) & 0xffff) + "]");
   //         pp.println("frame_count:     " + Utils.hex_value(frame_count, 4));
   //         pp.println("depth:           " + Utils.hex_value(depth, 4));

   //         avcc.print(verbose);

   //         pp.leave();
   //      }
   //   }
   //}

   //public static class VisualSampleEntry extends SampleEntry {
   //   AVC1 avc1;

   //   public VisualSampleEntry(AVC1 avc1) {
   //      this.avc1 = avc1;
   //   }

   //   public VisualSampleEntry(MP4File mp4, Box parent, byte data[]) {
   //      avc1 = (AVC1) Box.parse(mp4, parent, AVC1.get(mp4, parent, data));
   //   }

   //   public void write(ByteOutput bo) {
   //      avc1.write(bo);
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      if (verbose) {
   //         avc1.print(verbose);
   //      }
   //   }
   //}

   //public static class SampleEntry {
   //   public static SampleEntry get(MP4File mp4, Box parent, int handler_type, ByteInput bi) {
   //      switch (handler_type) {
   //      case HANDLER_SOUND:
   //         return new AudioSampleEntry(mp4, parent, bi.remaining_data());
   //      case HANDLER_VIDEO:
   //         return new VisualSampleEntry(mp4, parent, bi.remaining_data());
   //      }

   //      return null;
   //   }

   //   public void write(ByteOutput bo) {}

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();
   //   }
   //}

   //public static class STSD extends Box {
   //   int entry_count;
   //   SampleEntry entries[];

   //   public STSD(SampleEntry entries[]) {
   //      super(STSD_BOX);

   //      this.entries = entries;
   //      this.entry_count = entries.length;
   //   }

   //   public int handler_type(MP4File mp4, Box parent) {
   //      Box stbl = parent;

   //      if (stbl.type() != STBL_BOX) ERR.log("expected STBL box as parent for STSD");
   //      Box minf = stbl.parent();

   //      if (minf.type() != MINF_BOX) ERR.log("expected MINF box as parent for STBL");

   //      Box mdia = minf.parent();
   //      if (mdia.type() != MDIA_BOX) ERR.log("expected MDIA box as parent for MINF");

   //      HDLR handler = (HDLR)((ContainerBox) mdia).lookup_box_by_type(HDLR_BOX);

   //      if (handler != null) return handler.handler_type();

   //      return -1;
   //   }

   //   public STSD(MP4File mp4, Box parent, byte data[]) {
   //      super(parent, data.length, STSD_BOX, data);

   //      ByteInput bi = new ByteInput(data);

   //      //skip version
   //      bi.skip(4);

   //      entry_count = bi.read_4();

   //      entries = new SampleEntry[entry_count];

   //      int handler_type = handler_type(mp4, parent);

   //      for (int i = 0; i < entry_count; i++) {
   //         entries[i] = SampleEntry.get(mp4, parent, handler_type, bi);
   //      }
   //   }

   //   public static Box get(MP4File mp4, Box parent, byte data[]) {
   //      return new STSD(mp4, parent, data);
   //   }

   //   public void write_data(ByteOutput bo) {
   //      bo.write_zero(4);

   //      bo.write_4(entry_count);

   //      for (int i = 0; i < entry_count; i++) {
   //         SampleEntry entry = entries[i];
   //         entry.write(bo);
   //      }
   //   }

   //   public void print(boolean verbose) {
   //      PaddedPrinter pp = Shell.get_pp();

   //      pp.println("box: " + full_name());
   //      if (verbose) {
   //         pp.println("len: " + Utils.hex_value(data.length, 8));
   //         pp.pad(2, "");

   //         pp.println("entry_count: " + Utils.hex_value(entry_count, 4));

   //         for (int i = 0; i < entry_count; i++) {
   //            SampleEntry se = entries[i];
   //            se.print(verbose);
   //         }

   //         pp.leave();
   //      }
   //   }
   //}

   ////main mp4 implementation
   //public static ContainerBox MOOV() {
   //   return new ContainerBox(MOOV_BOX);
   //}

   //public static ContainerBox TRAK() {
   //   return new ContainerBox(TRAK_BOX);
   //}

   //public static ContainerBox MVEX() {
   //   return new ContainerBox(MVEX_BOX);
   //}

   //public static ContainerBox MDIA() {
   //   return new ContainerBox(MDIA_BOX);
   //}

   //public static ContainerBox MINF() {
   //   return new ContainerBox(MINF_BOX);
   //}

   //public static ContainerBox DINF() {
   //   return new ContainerBox(DINF_BOX);
   //}

   //public static ContainerBox STBL() {
   //   return new ContainerBox(STBL_BOX);
   //}

   //public static Vector < Box > read_boxes(byte data[]) {
   //   Vector < Box > boxes = new Vector < Box > ();

   //   ByteInput bi = new ByteInput(data);

   //   int len = data.length;

   //   while (len > 0) {
   //      bi.skip(4);

   //      int type = bi.peek_4();

   //      bi.skip(-4);

   //      Box box = new Box(bi);
   //      boxes.add(box);

   //      len -= box.len() + BOX_HDR_SIZE;
   //   }

   //   return boxes;
   //}

   //public static String int2str(int val) {
   //   byte sdata[] = new byte[4];
   //   sdata[0] = (byte)((val >> 24) & 0xff);
   //   sdata[1] = (byte)((val >> 16) & 0xff);
   //   sdata[2] = (byte)((val >> 8) & 0xff);
   //   sdata[3] = (byte)((val) & 0xff);

   //   return new String(sdata);
   //}

   //public static int str2int(String s) {
   //   byte tab[] = s.getBytes();

   //   return (new ByteInput(tab)).read_4();
   //}

   //public MP4File(String path, byte data[]) {
   //   this.path = path;

   //   if (data != null) {
   //      this.cbox = (ContainerBox) ContainerBox.get(this, null, ROOT_MP4_NAME, CONTAINER_BOX, data);
   //   } else {
   //      this.cbox = new ContainerBox(ROOT_MP4_NAME);
   //   }
   //}

   //public MP4File(String path) {
   //   this(path, null);
   //}

   //public String path() {
   //   return path;
   //}

   //public void print() {
   //   print(true);
   //}

   //public void print(boolean verbose) {
   //   PaddedPrinter pp = Shell.get_pp();

   //   pp.println("### FILE: " + path);

   //   pp.pad(1, "");
   //   cbox.print(verbose);
   //   pp.leave();
   //}

   //public static MP4File from_file(String path) {
   //   byte data[] = Utils.load_file(path);

   //   if (data != null) {
   //      return new MP4File(path, data);
   //   }

   //   //unknown MP4 file
   //   return null;
   //}

   public static String duration_str(long total_sec) {
      long hours = total_sec / 3600L;
      long minutes = total_sec / 60L - (hours * 60L);
      long seconds = total_sec - (minutes * 60L);

      String res = "";

      res += hours + "h ";
      res += minutes + "m ";
      res += seconds + "s";

      return res;
   }

   //public void add_box(Box b) {
   //   cbox.add_box(b);
   //}

   //public static String[] tokenize_path(String path) {
   //   return Utils.tokenize(path, ".");
   //}

   //public Box lookup_box_by_name(String name) {
   //   return cbox.lookup_box_by_name(name);
   //}

   //public Box get_box(String boxpath) {
   //   String path_elem[] = tokenize_path(boxpath);

   //   Box curpos = cbox;
   //   Box res = null;

   //   for (int i = 0; i < path_elem.length; i++) {
   //      if (curpos instanceof ContainerBox) {
   //         res = ((ContainerBox) curpos).lookup_box_by_name(path_elem[i]);
   //      }

   //      if (res == null) break;

   //      curpos = res;
   //   }

   //   return res;
   //}

   //public TRUN get_trun() {
   //   Box box = get_box("moof.traf.trun");

   //   if (box != null) {
   //      return (TRUN) box;
   //   }

   //   return null;
   //}

   //public TFHD get_tfhd() {
   //   Box box = get_box("moof.traf.tfhd");

   //   if (box != null) {
   //      return (TFHD) box;
   //   }

   //   return null;
   //}

   //public ContainerBox get_cbox() {
   //   return cbox;
   //}

   //public SampleEncryptionBox get_seb() {
   //   Box box = get_box("moof.traf.SampleEncryptionBox");

   //   if (box != null) {
   //      return (SampleEncryptionBox) box;
   //   }

   //   return null;
   //}

   //public MDAT get_mdat() {
   //   Box box = get_box("mdat");

   //   if (box != null) {
   //      return (MDAT) box;
   //   }

   //   return null;
   //}

   //public boolean verify_sample_cnt() {
   //   TRUN trun = get_trun();
   //   SampleEncryptionBox seb = get_seb();

   //   if ((trun != null) && (seb != null)) {
   //      return trun.sample_cnt() == seb.sample_cnt();
   //   }

   //   return false;
   //}

   //public boolean verify_mdat() {
   //   TRUN trun = get_trun();
   //   MDAT mdat = get_mdat();

   //   if ((trun != null) && (mdat != null)) {
   //      int total_len = 0;

   //      for (int i = 0; i < trun.sample_cnt(); i++) {
   //         SampleInfo si = trun.get_sinfo(i);

   //         total_len += si.size();
   //      }

   //      int mdat_len = mdat.data().length;

   //      return total_len == mdat_len;
   //   }

   //   return false;
   //}

   //public void decrypt(Codec codec, byte content_key[]) throws Throwable {
   //   codec.decrypt(this, content_key);

   //   clean_decrypt_info();
   //}

   //public int append_fragment(MP4File fragmp4) throws Throwable {
   //   int size = -1;

   //   String outfile = path();

   //   ContainerBox cb = fragmp4.get_cbox();

   //   if (cb != null) {
   //      ByteOutput bo = new ByteOutput(BYTEOUTPUT_SIZE);

   //      for (int i = 0; i < cb.cnt(); i++) {
   //         Box box = cb.get(i);
   //         box.write(bo);
   //      }

   //      byte data[] = bo.bytes();

   //      FileOutputStream fos = new FileOutputStream(outfile, true);
   //      fos.write(data);
   //      fos.close();

   //      size = data.length;
   //   }

   //   return size;
   //}

   //public void clean_decrypt_info() {
   //   SampleEncryptionBox seb = get_seb();

   //   if (seb != null) {
   //      byte uuid[] = seb.uuid();
   //      byte user_data[] = seb.user_data();

   //      //change UUID to mark content as not encrypted
   //      POCInfo.replace_array_content(uuid, POCInfo.UUID);

   //      //clear user data
   //      POCInfo.replace_array_content(user_data, POCInfo.MSG);

   //      seb.changed();
   //   }
   //}

   //public int get_trackid() {
   //   TFHD tfhd = get_tfhd();

   //   if (tfhd != null) {
   //      return tfhd.trackid();
   //   }

   //   return -1;
   //}

   //public void set_trackid(int track_id) {
   //   TFHD tfhd = get_tfhd();

   //   if (tfhd != null) {
   //      tfhd.set_trackid(track_id);
   //      tfhd.changed();
   //   }
   //}

   //public void save(String outfile) throws Throwable {
   //   ByteOutput bo = new ByteOutput(BYTEOUTPUT_SIZE);

   //   ContainerBox cb = (ContainerBox) cbox;

   //   for (int i = 0; i < cb.cnt(); i++) {
   //      Box box = cb.get(i);
   //      box.write(bo);
   //   }

   //   FileOutputStream fos = new FileOutputStream(outfile, false);
   //   fos.write(bo.bytes(), 0, bo.length());
   //   fos.close();
   //}

   //public void save() throws Throwable {
   //   save(path());
   //}
}
