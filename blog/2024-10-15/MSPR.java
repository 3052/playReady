package mod.mspr;

//import agsecres.tool.*;
//import agsecres.helper.*;
import java.lang.*;
import java.io.*;
import java.math.*;
import java.security.*;
import java.util.*;
import java.math.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class MSPR {
   public static String build_license_request(Device dev,String wrmheader,String nonce,String keydata,String cipherdata) throws Throwable {
      String digest_content=build_digest_content(wrmheader,nonce,keydata,cipherdata);
      byte digest_bytes[]=Crypto.SHA256(digest_content.getBytes());
      String digest=Crypto.base64_encode(digest_bytes);
   }
}
