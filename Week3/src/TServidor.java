import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

/**
 * Created by MGonc on 29/02/16.
 */
public class TServidor extends Thread {

    private final int ct;
    protected final Socket s;

    public TServidor(Socket s, int c) {
        ct = c;
        this.s=s;
    }

    /** Parse byte[] with format initilization vector, encrypted data and Mac */
    private static void parseArray(byte[] file, byte[] cont, byte[] mac, byte[] iv, int size){
        System.arraycopy(file, 0, iv, 0, iv.length);
        System.arraycopy(file, iv.length, cont, 0, size);
        System.arraycopy(file, size + iv.length, mac, 0, mac.length);
    }

    public void run() {
        try {
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());

            /** Receive BigInteger from client */
            BigInteger cG = (BigInteger) ois.readObject();

            /** Generate Random y */
            BigInteger y = new BigInteger(1024, new Random());

            /** Generate big integer */
            KeyAggrement kA = new KeyAggrement();
            BigInteger mG = kA.generateMyInteger(y);

            /** Send BigInteger to server */
            oos.writeObject(mG);

            /** Calculate key */
            BigInteger bInt = kA.negociateInt(cG,y);

            /** Convert Big Integer to byte[] */
            byte[] masterSecret = bInt.toByteArray();

            /** Using hash function */
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            byte[] bKey = hash.digest(masterSecret);

            /** Generate secret key */
            SecretKey sk = new SecretKeySpec(bKey, "AES");

            byte[] km = new byte[16];
            byte[] kk = new byte[16];
            byte[] tmp = sk.getEncoded();

            /** Divide original key */
            System.arraycopy(tmp, 0, kk, 0, 16);
            System.arraycopy(tmp, 16, km, 0, 16);

            /** Generate mac and encript key*/
            SecretKey kMac = new SecretKeySpec(km, "AES");
            SecretKey kKey = new SecretKeySpec(kk, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

            try {
                while (true) {

                    byte[] data = (byte[]) ois.readObject();

                    byte[] iv = new byte[16];
                    byte[] mac = new byte[32];
                    int size = data.length - 16 - 32;
                    byte[] cont = new byte[size];

                    parseArray(data, cont, mac, iv, size);

                    /** Initialize the Cipher for Decryption */
                    cipher.init(Cipher.DECRYPT_MODE, kKey, new IvParameterSpec(iv));

                    /** Decrypt the Data */
                    byte[] result = cipher.doFinal(cont);

                    /** Generate Mac */
                    Mac m = Mac.getInstance("HmacSHA256");
                    m.init(kMac);
                    byte[] recoveryMac = m.doFinal(cont);

                    /** Compare Computed MAC vs Recovered MAC */
                    if (Arrays.equals(mac, recoveryMac)) {
                        /** MAC Verification Passed */
                        System.out.println(ct + " : " + new String(result));
                    } else { System.out.println("No match between MACs!"); }
                }
            } catch (EOFException e) {
                System.out.println("["+ct + "]");
            } finally {
                if (ois!=null) ois.close();
                if (oos!=null) oos.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
