import java.io.*;
import javax.crypto.*;
import java.security.*;
import java.util.Arrays;
import javax.crypto.spec.*;
import java.security.cert.*;
import java.security.spec.*;
import static java.security.KeyStore.*;

/**
 * Created by MGonc on 25/02/16.
 */
public class EncryptDecrypt {

    /** Constructs byte[] with initilization vector, encrypted data and Mac */
    private static byte[] constructArray(byte[] data, byte[] mac, IvParameterSpec iv){
        byte[] result = new byte[data.length + 16 + 32];
        System.arraycopy(iv.getIV(), 0, result, 0, 16);
        System.arraycopy(data, 0, result, 16, data.length);
        System.arraycopy(mac, 0, result, data.length + 16, 32);
        return result;
    }

    /** Parse byte[] with format initilization vector, encrypted data and Mac */
    private static void parseArray(byte[] file, byte[] cont, byte[] mac, byte[] iv, int size){
        System.arraycopy(file, 0, iv, 0, 16);
        System.arraycopy(file, 16, cont, 0, size);
        System.arraycopy(file, size + 16, mac, 0, 32);
    }

    public static void encryptOrDecrypt(String keystore, String password, int mode, String input, String output) {

        /** Load Secret key */
        SecretKey key = loadSecretKey(keystore, password);

        /** Create a Cipher by specifying the following parameters
            * a. Algorithm name - here it is AES
            * b. Mode - here it is CBC mode
            * c. Padding - e.g. PKCS5
         */
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error creating cipher" + e + "\n");
        } catch (NoSuchPaddingException e) {
            System.out.println("Error creating cipher" + e + "\n");
        }

        if(key == null || cipher == null){
            System.out.println("Can't read " + keystore + " file.");
        }
        else if (mode == Cipher.ENCRYPT_MODE) {
            encrypt(cipher, key, input, output);
        } else if (mode == Cipher.DECRYPT_MODE) {
            decrypt(cipher, key, input, output);
        }
    }

    public static void encrypt(Cipher cipher, SecretKey key, String input, String output) {
        try{
            /** Load file for encrypt */
            byte[] file = loadFile(input);
            if(file == null){ System.out.println("Can't read " + input + " file."); return; }

            /** Generates initialization vector */
            SecureRandom r = new SecureRandom();
            IvParameterSpec iv = new IvParameterSpec(r.generateSeed(16));
            byte[] km = new byte[16];
            byte[] kk = new byte[16];
            byte[] tmp = key.getEncoded();

            /** Divide original key */
            System.arraycopy(tmp, 0, kk, 0, 16);
            System.arraycopy(tmp, 16, km, 0, 16);

            /** Generate mac and encript key*/
            SecretKey kmac = new SecretKeySpec(km, "AES");
            SecretKey kkey = new SecretKeySpec(kk, "AES");

            /** Cipher initialization */
            cipher.init(Cipher.ENCRYPT_MODE, kkey, iv);

            /** Encrypt the Data */
            byte[] data = cipher.doFinal(file);

            /** Generates Mac */
            byte[] mac = generateMac(kmac, data);
            byte[] result = constructArray(data, mac, iv);
            writeFile(result, output);

            System.out.println("File encrypted to \"" + output + "\"");
        } catch (IOException | BadPaddingException e) {
            System.out.println("Error encrypt mode!" + e + "\n");
        } catch ( IllegalBlockSizeException e) {
            System.out.println("Error encrypt mode!" + e + "\n");
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public static void decrypt(Cipher cipher, SecretKey key, String input, String output) {
        try{
            /** Load file for encrypt */
            byte[] file = loadFile(input);
            if(file == null){ System.out.println("Can't read " + input + " file."); return; }

            byte[] iv = new byte[16];
            byte[] mac = new byte[32];
            int size = file.length - 16 - 32;
            byte[] cont = new byte[size];

            parseArray(file, cont, mac, iv, size);

            byte[] km = new byte[16];
            byte[] kk = new byte[16];
            byte[] tmp = key.getEncoded();

            /** Divide original key */
            System.arraycopy(tmp, 0, kk, 0, 16);
            System.arraycopy(tmp, 16, km, 0, 16);

            /** Generate mac and encript key*/
            SecretKey kmac = new SecretKeySpec(km, "AES");
            SecretKey kkey = new SecretKeySpec(kk, "AES");

            /** Initialize the Cipher for Decryption */
            cipher.init(Cipher.DECRYPT_MODE, kkey, new IvParameterSpec(iv));

            /** Decrypt the Data */
            byte[] result = cipher.doFinal(cont);

            /** Compare Computed MAC vs Recovered MAC */
            if (Arrays.equals(mac, generateMac(kmac, cont))) {
                /** MAC Verification Passed */
                writeFile(result, output);
                System.out.println("File decrypted to \"" + output + "\"");
            } else {
                System.out.println("No match between MACs!");
            }
        } catch (IOException | BadPaddingException | InvalidAlgorithmParameterException e) {
            System.out.println("Error decrypt mode!" + e + "\n");
        } catch (InvalidKeyException | IllegalBlockSizeException e) {
            System.out.println("Error decrypt mode!" + e + "\n");
        }
    }

    private static SecretKey loadSecretKey(String keystore, String password) {
        try {
            File f = new File(keystore);
            KeyStore ks = getInstance("JCEKS");

            if (f.exists()) {
                ks.load(new FileInputStream(f), password.toCharArray());
            }

            PasswordProtection ps = new PasswordProtection(password.toCharArray());
            SecretKeyEntry ent = (SecretKeyEntry) ks.getEntry("SecretKey", ps);
            return ent.getSecretKey();
        } catch (CertificateException | NoSuchAlgorithmException | IOException
                | UnrecoverableEntryException | KeyStoreException e) {
            System.out.println("Error loading secret key!" + e + "\n");
            return null;
        }
    }

    private static void generateKey(String keystore, String password) {
        try {
            /** Generate salt */
            byte[] salt = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(salt);

            /** Generate secret key */
            SecretKeyFactory sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 32768, 256);
            SecretKey tmp = sf.generateSecret(spec);
            SecretKey sk = new SecretKeySpec(tmp.getEncoded(), "AES");

            /** Generate and keep KeyStore */
            KeyStore ks = getInstance("JCEKS");
            File f = new File(keystore);

            /** Initialize keystore */
            if (f.exists()) {
                ks.load(new FileInputStream(f), password.toCharArray());
            } else { ks.load(null, null); }

            SecretKeyEntry se = new SecretKeyEntry(sk);

            PasswordProtection ps = new PasswordProtection(password.toCharArray());
            ks.setEntry("SecretKey", se, ps);
            ks.store(new FileOutputStream(f), password.toCharArray());
        } catch (CertificateException | NoSuchAlgorithmException | IOException | InvalidKeySpecException
                | KeyStoreException e) {
            System.out.println("Error generating secret key!" + e + "\n");
        }
    }

    private static byte[] generateMac(Key k, byte[] cont) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(k);
            return mac.doFinal(cont);
        } catch (InvalidKeyException e) {
            System.out.println("Error generating Mac!" + e + "\n");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error generating Mac!" + e + "\n");
        }
        return null;
    }

    private static byte[] loadFile(String fname) throws IOException{
        try {
            File f = new File(fname);
            FileInputStream fin = new FileInputStream(f);
            byte[] bFile = new byte[(int) f.length()];
            fin.read(bFile);
            fin.close();
            return bFile;
        } catch (FileNotFoundException e) {
            System.out.println("File " + fname + " doesn't exists.");
            return null;
        }
    }

    private static void writeFile(byte[] in, String fname) throws IOException {
        FileOutputStream out = new FileOutputStream(fname);
        out.write(in);
        out.close();
    }

    public static void main(String[] args) throws Exception {
        switch(args[0]) {
            case "-genkey":
                if (args.length == 3) {
                    generateKey(args[1], args[2]);
                } else { System.out.println("Insufficient arguments!"); }
                break;
            case "-enc":
                if (args.length == 5) {
                    encryptOrDecrypt(args[1], args[2], Cipher.ENCRYPT_MODE, args[3], args[4]);
                } else { System.out.println("Insufficient arguments!"); }
                break;
            case "-dec":
                if (args.length == 5) {
                    encryptOrDecrypt(args[1], args[2], Cipher.DECRYPT_MODE, args[3], args[4]);
                } else { System.out.println("Insufficient arguments!"); }
                break;
        }
    }
}
