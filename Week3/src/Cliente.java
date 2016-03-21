import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.math.*;
import java.net.*;
import java.security.*;
import java.util.Random;

/**
 * Created by MGonc on 29/02/16.
 */
public class Cliente {

    /** Constructs byte[] with initilization vector, encrypted data and Mac */
    private static byte[] constructArray(byte[] data, byte[] mac, IvParameterSpec iv){
        byte[] i = iv.getIV();
        byte[] result = new byte[i.length + data.length + mac.length];
        System.arraycopy(i, 0, result, 0, 16);
        System.arraycopy(data, 0, result, i.length, data.length);
        System.arraycopy(mac, 0, result, data.length + i.length, mac.length);
        return result;
    }

    public static void main(String []args) {
        try {
            Socket s = new Socket("localhost",4567);
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in, "UTF-8"));
            String test;

            /** Generate Random x */
            BigInteger x = new BigInteger(1024, new Random());

            /** Generate big integer */
            KeyAggrement kA = new KeyAggrement();
            BigInteger mG = kA.generateMyInteger(x);

            /** Send BigInteger to server */
            oos.writeObject(mG);

            /** Receive BigInteger from server */
            BigInteger sG = (BigInteger) ois.readObject();

            /** Calculate key */
            BigInteger bInt = kA.negociateInt(sG,x);

            /** Convert Big Integer to byte[] */
            byte[] masterSecret = bInt.toByteArray();

            /** Using hash function */
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            byte[] bKey = hash.digest(masterSecret);

            /** Generate secret key */
            SecretKey sk = new SecretKeySpec(bKey, "AES");

            /** Generates initialization vector */
            SecureRandom r = new SecureRandom();
            IvParameterSpec iv = new IvParameterSpec(r.generateSeed(16));

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

            while((test = stdIn.readLine()) != null) {
                /** Encrypt input data */
                cipher.init(Cipher.ENCRYPT_MODE, kKey, iv);
                byte[] dEncrypt = cipher.doFinal(test.getBytes());

                /** Generate Mac */
                Mac m = Mac.getInstance("HmacSHA256");
                m.init(kMac);
                byte[] mac = m.doFinal(dEncrypt);

                /** Generate Data Array */
                byte[] data = constructArray(dEncrypt,mac,iv);

                /** Send message */
                oos.writeObject(data);
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}