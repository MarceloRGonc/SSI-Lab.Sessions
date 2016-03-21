import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.EOFException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Created by MGonc on 29/02/16.
 */
public class TServidor extends Thread {

    private final int ct;
    protected final Socket s;

    public TServidor(Socket ss, int c) {
        ct = c;
        s = ss;
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

            /** Load key pair */
            KGenerator kg = new KGenerator();
            KeyPair keypair = kg.keyGeneratorDH();

            /** Load private key */
            PrivateKey privateKey = CertValidator.getPrivateKey("newServer.p12","Server");

            /** Receive public key from client */
            byte[] cPK = (byte[]) ois.readObject();

            /** Receive certificate path from client */
            CertPath clientPCert = (CertPath) ois.readObject();
            X509Certificate ca = CertValidator.getCertificate("newCA.cer");

            /** Certificate validation */
            if (!CertValidator.validateCert(ca, clientPCert)) {
                System.err.println("Wrong certificate!");
                System.exit(0);
            }

            /** Send public key to client */
            byte[] sPKey = keypair.getPublic().getEncoded();
            oos.writeObject(sPKey);

            /** Send certificate to client */
            CertPath cert = CertValidator.getCertificate("newServer.p12", "Server");
            oos.writeObject(cert);

            /** Create Signature */
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(privateKey);
            sig.update(sPKey);
            sig.update(cPK);

            /** Send signature of server public key and client public key */
            oos.writeObject(sig.sign());

            /** Reveive signature of client public key and server public key */
            byte[] sigClient = (byte[]) ois.readObject();

            Signature sigFromServer = Signature.getInstance("SHA256withRSA");
            sigFromServer.initVerify(clientPCert.getCertificates().get(0).getPublicKey());
            sigFromServer.update(cPK);
            sigFromServer.update(sPKey);

            if (!sigFromServer.verify(sigClient)) {
                System.err.println("[Server] Wrong signature");
                System.exit(0);
            }

            KeyFactory sKeyFac = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(cPK);
            PublicKey cPubKey = sKeyFac.generatePublic(x509KeySpec);

            KeyAgreement sKeyAgree = KeyAgreement.getInstance("DH");
            sKeyAgree.init(keypair.getPrivate());

            sKeyAgree.doPhase(cPubKey, true);

            byte[] secret = sKeyAgree.generateSecret();

            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] masterKey = md.digest(secret);

            /** Get private key */
            SecretKey sk = new SecretKeySpec(masterKey, "AES");

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

