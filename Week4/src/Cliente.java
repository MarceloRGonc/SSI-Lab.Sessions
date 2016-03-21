import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.math.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
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

            /** Load key pair */
            KGenerator kg = new KGenerator();
            KeyPair keypair = kg.keyGeneratorDH();

            /** Load signature key pair */
            KeyPair signatureKeys = SignatureKeypairGenerator.loadKeyFile("Client");

            /** Send public key to server */
            byte[] cPKey = keypair.getPublic().getEncoded();
            oos.writeObject(cPKey);

            /** Receive public key from server */
            byte[] sPK = (byte[]) ois.readObject();

            /** Receive signature public key from server */
            KeyFactory keyFactRSA = KeyFactory.getInstance("RSA");
            PublicKey signatureSPublicKey = keyFactRSA.generatePublic(
                    new X509EncodedKeySpec(SignatureKeypairGenerator.loadFile("Server.pub")));

            /** Signature of server public key and client public key */
            byte[] sigServer = (byte[]) ois.readObject();

            Signature sigFromServer = Signature.getInstance("SHA1withRSA");
            sigFromServer.initVerify(signatureSPublicKey);
            sigFromServer.update(sPK);
            sigFromServer.update(cPKey);

            if (!sigFromServer.verify(sigServer)) {
                System.err.println("[Client] Wrong signature");
                System.exit(0);
            }

            /** Create Signature */
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(signatureKeys.getPrivate());
            sig.update(cPKey);
            sig.update(sPK);

            /** Send signature of server public key and client public key */
            oos.writeObject(sig.sign());

            KeyFactory cKeyFac = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(sPK);
            PublicKey sPubKey = cKeyFac.generatePublic(x509KeySpec);

            KeyAgreement cKeyAgree = KeyAgreement.getInstance("DH");
            cKeyAgree.init(keypair.getPrivate());

            cKeyAgree.doPhase(sPubKey, true);

            byte[] secret = cKeyAgree.generateSecret();

            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] masterKey = md.digest(secret);

            /** Send public key with signature */

            /** Get private key */
            SecretKey sk = new SecretKeySpec(masterKey, "AES");

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

            Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");

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