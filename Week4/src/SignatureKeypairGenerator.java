import java.io.*;
import java.security.*;
import java.security.spec.*;

/**
 * Created by MGonc on 11/03/16.
 */
public class SignatureKeypairGenerator {

    public static void main(String[] args) {
        keyGeneratorFile(args[0]);
        loadKeyFile(args[0]);
    }

    private static void writeFile(byte[] in, String fname) throws IOException {
        FileOutputStream out = new FileOutputStream(fname);
        out.write(in);
        out.close();
    }

    public static byte[] loadFile(String fname) throws IOException{
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

    public static void keyGeneratorFile(String filename) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            KeyPair kp = kpg.generateKeyPair();

            X509EncodedKeySpec eksPub = new X509EncodedKeySpec(kp.getPublic().getEncoded());
            PKCS8EncodedKeySpec eksPriv = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());

            /** Writes keys into files */
            writeFile(eksPub.getEncoded(), filename + ".pub");
            writeFile(eksPriv.getEncoded(), filename + ".priv");

        } catch (IOException e) {
            System.out.println("Error writing files! - IOException");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error KeyPairGenerator! - NoSuchAlgorithmException");
        }
    }

    public static KeyPair loadKeyFile(String filename) {
        KeyPair kp = null;
        try {
            /** Load Files */
            byte[] pubKey = loadFile(filename + ".pub");
            byte[] privKey = loadFile(filename + ".priv");

            X509EncodedKeySpec eksPub = new X509EncodedKeySpec(pubKey);
            PKCS8EncodedKeySpec eksPriv = new PKCS8EncodedKeySpec(privKey);

            /** Generates Keys */
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(eksPub);
            PrivateKey privateKey = kf.generatePrivate(eksPriv);

            /** Create key pair */
            kp = new KeyPair(publicKey, privateKey);
        } catch (IOException e) {
            System.out.println("Error loading files! - IOException");
        } catch (InvalidKeySpecException e) {
            System.out.println("Error generating keyss! - InvalidKeySpecException");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error KeyFactory! - NoSuchAlgorithmException");
        }
        return kp;
    }
}

