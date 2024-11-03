package mod.mspr;

import agsecres.tool.*;
import java.lang.*;
import java.io.*;

public class FileCache {
 public static final String DEFAULT_CACHE_DIR = "content";

 //required content
 public static final String URL_FILE      = "url.txt";
 public static final String LS_FILE       = "ls.txt";
 
 //downloaded and generated content
 public static final String KEY_FILE      = "key.txt";

 public static final String VIDEO_DIR     = "video";
 public static final String AUDIO_DIR     = "audio";

 public static final String QUALITY_DIR   = "q";

 public static final String DEBUG_DIR     = "debug";
 public static final String TMP_DIR       = "tmp";

 public static final String MANIFEST_FILE = "Manifest.ism";

 public static final String INFO_FILE     = "Info.json";


 public static final String MP4_FILE      = "movie.mp4";

 public static String content_dir() {
  String cache_dir=Vars.get_str("CONTENT_DIR");

  if (cache_dir==null) {
   cache_dir=DEFAULT_CACHE_DIR;
  }

  return cache_dir;
 }

 public static String tmp_dir() {
  String tmp=content_dir()+File.separatorChar+TMP_DIR;

  return tmp;
 }

 public static String asset_dir(String assetname) {
  String cache_dir=content_dir();

  String dir=cache_dir+File.separatorChar+assetname;

  return dir;
 }

 public static String audio_dir(String assetname) {
  String dir=asset_dir(assetname)+File.separatorChar+AUDIO_DIR;

  return dir;
 }

 public static String audio_dir(String assetname,String audioname) {
  String dir=asset_dir(assetname)+File.separatorChar+AUDIO_DIR+File.separatorChar+audioname;

  return dir;
 }

 public static String audio_qdir(String assetname,String audioname,String quality) {
  String dir=audio_dir(assetname,audioname)+File.separatorChar+QUALITY_DIR+quality;

  return dir;
 }

 public static String debug_dir(String assetname) {
  String dir=asset_dir(assetname)+File.separatorChar+DEBUG_DIR;

  return dir;
 }

 public static String debug_file(String assetname,String debugfile) {
  String dir=debug_dir(assetname);
  Utils.mkdir(dir);

  String file=dir+File.separatorChar+debugfile;

  return file;
 }

 public static String manifest_filename(String assetname) {
  String file=asset_dir(assetname)+File.separatorChar+MANIFEST_FILE;

  return file;
 }

 public static String info_filename(String assetname) {
  String file=asset_dir(assetname)+File.separatorChar+INFO_FILE;

  return file;
 }

 public static String url_filename(String assetname) {
  String file=asset_dir(assetname)+File.separatorChar+URL_FILE;

  return file;
 }

 public static String lsurl_filename(String assetname) {
  String file=asset_dir(assetname)+File.separatorChar+LS_FILE;

  return file;
 }

 public static String key_filename(String assetname) {
  String file=asset_dir(assetname)+File.separatorChar+KEY_FILE;

  return file;
 }

 public static String local_license_filename(String assetname) {
  String local_license=Vars.get_str("MSPR_LOCAL_LICENSE");

  if (local_license!=null) {
   String file=asset_dir(assetname)+File.separatorChar+local_license;

   return file;
  }
 
  return null;
 }

 public static String mp4_filename(String assetname) {
  String file=asset_dir(assetname)+File.separatorChar+MP4_FILE;

  return file;
 }

 public static String audio_filename(String assetname,String audioname,String quality,int idx) {
  String file=audio_qdir(assetname,audioname,quality)+File.separatorChar+idx;

  return file;
 }

 public static String video_dir(String assetname) {
  String dir=asset_dir(assetname)+File.separatorChar+VIDEO_DIR;

  return dir;
 }

 public static String video_qdir(String assetname,String quality) {
  String dir=video_dir(assetname)+File.separatorChar+QUALITY_DIR+quality;

  return dir;
 }

 public static String video_filename(String assetname,String quality,int idx) {
  String file=video_qdir(assetname,quality)+File.separatorChar+idx;

  return file;
 }

 public static String tmp_filename(String name) {
  String file=tmp_dir()+File.separatorChar+name;

  return file;
 }

 public static void make_dirs(String assetname) {
  String tmpdir=tmp_dir();

  Utils.mkdir(tmpdir);

  String adir=audio_dir(assetname);
  String vdir=video_dir(assetname);
  String ddir=debug_dir(assetname);

  Utils.mkdir(adir);
  Utils.mkdir(vdir);
  Utils.mkdir(ddir);
 }

 public static void make_dirs(String assetname,String audioname,String aquality,String vquality) {
  String aqdir=audio_qdir(assetname,audioname,aquality);
  String vqdir=video_qdir(assetname,vquality);

  Utils.mkdir(aqdir);
  Utils.mkdir(vqdir);
 }

 //check if both files (audio / video) exist sfor given fragment idx
 public static boolean fragment_exists(String assetid,String audio_name,String audio_quality,String video_quality,int idx) {
  String vfragpath=FileCache.video_filename(assetid,video_quality,idx);
  String afragpath=FileCache.audio_filename(assetid,audio_name,audio_quality,idx);

  return Utils.file_exists(afragpath)&&Utils.file_exists(vfragpath);
 }
}
