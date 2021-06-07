import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Arrays;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class StrongAES
{
    static private void processFile(Cipher ci,InputStream in,OutputStream out)
            throws javax.crypto.IllegalBlockSizeException,
            javax.crypto.BadPaddingException,
            java.io.IOException
    {
        byte[] ibuf = new byte[1024];
        int len;
        while ((len = in.read(ibuf)) != -1) {
            byte[] obuf = ci.update(ibuf, 0, len);
            //System.out.println("encoded : " + new String(Base64.getEncoder().encode(obuf)));
            //System.out.println("encoded1 : " + new String(obuf, StandardCharsets.UTF_8));
            //if ( obuf != null ) out.write(Base64.getEncoder().encode(obuf));
            if ( obuf != null ) out.write(obuf);
        }
        byte[] obuf = ci.doFinal();
        //System.out.println("encoded : " + new String(Base64.getEncoder().encode(obuf)));
        //if ( obuf != null ) out.write(Base64.getEncoder().encode(obuf));
        if ( obuf != null ) out.write(obuf);
    }

    static private void processFileDecrypt(Cipher ci,InputStream in,OutputStream out)
            throws javax.crypto.IllegalBlockSizeException,
            javax.crypto.BadPaddingException,
            java.io.IOException
    {
        byte[] ibuf = new byte[1024];
        int len;
        while ((len = in.read(ibuf)) != -1) {
            //ibuf = Base64.getDecoder().decode(ibuf);
            byte[] obuf = ci.update(ibuf, 0, len);
            //System.out.println("encoded : " + new String(Base64.getEncoder().encode(obuf)));
            //if ( obuf != null ) out.write(Base64.getEncoder().encode(obuf));
            if ( obuf != null ) out.write(obuf);
        }
        byte[] obuf = ci.doFinal();
        //System.out.println("encoded : " + new String(Base64.getEncoder().encode(obuf)));
        //if ( obuf != null ) out.write(Base64.getEncoder().encode(obuf));
        if ( obuf != null ) out.write(obuf);
    }

    public void run()
    {
        try
        {
            String text = "Hello World";

            // Create key
            String key = "Bar12345Bar12345"; // 128 bit key
            Key aesKey = new SecretKeySpec(key.getBytes(), "AES");
            String keyStr = new String(Base64.getEncoder().encode(key.getBytes()));
            System.out.println("key : " + keyStr);

            // Craete iv
            String iv = "1234567890123456";
            IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes());
            String ivStr = new String(Base64.getEncoder().encode(iv.getBytes()));
            System.out.println("iv : " + ivStr);

            //Cipher ENCRYPT
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivspec);
            //String inputFile = "1.txt";
            String inputFile = "kiru_bday.zip";
            try (FileOutputStream out = new FileOutputStream(inputFile + ".enc")) {
                try (FileInputStream in = new FileInputStream(inputFile)) {
                    processFile(cipher, in, out);
                }
            }

            //Cipher DECRYPT
           /* cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, ivspec);

            inputFile = inputFile + ".enc";

            try (FileOutputStream out = new FileOutputStream(inputFile + ".ver")) {
                try (FileInputStream in = new FileInputStream(inputFile)) {
                    processFileDecrypt(cipher, in, out);
                }
            }*/

            //byte[] encrypted = cipher.doFinal(text.getBytes());
            //String encStr = new String(Base64.getEncoder().encode(encrypted));
            //System.out.println("enc : " + encStr);

            // decrypt the text
            /*
            byte[] decStr = Base64.getDecoder().decode(encStr);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, ivspec);
            String decrypted = new String(cipher.doFinal(decStr));
            System.err.println(decrypted);*/
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
    public static void main(String[] args)
    {
        StrongAES app = new StrongAES();
        app.run();
    }
}