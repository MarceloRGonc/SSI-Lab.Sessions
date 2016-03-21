import java.io.*;
import javax.crypto.*;
import java.security.*;
import java.security.cert.*;
import static java.security.KeyStore.*;

/**
 * Created by MGonc on 19/02/16.
 */
public class EncryptDecrypt {

    public static void encrypt(String key, String pass, String is, String os)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        encryptOrDecrypt(key, pass, Cipher.ENCRYPT_MODE, is, os);
    }

    public static void decrypt(String key, String pass, String is, String os)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        encryptOrDecrypt(key, pass, Cipher.DECRYPT_MODE, is, os);
    }

    public static void encryptOrDecrypt(String keystore, String password, int mode, String is, String os)
            throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IOException {

        File fkey = new File(keystore);

        if (!fkey.exists()) {
            System.out.println("Keystore " + keystore + " doesn't exists.");
            return;
        }

        FileInputStream infile;
        FileOutputStream outfile;

        try {
            infile = new FileInputStream(is);
            outfile = new FileOutputStream(os);
        } catch (FileNotFoundException e) {
            System.out.println("File " + is + " doesn't exists.");
            return;
        }

        SecretKey key = loadSecret(keystore, password);
        Cipher cipher = Cipher.getInstance("RC4");

        if(key == null){ return; }
        else if (mode == Cipher.ENCRYPT_MODE) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            CipherInputStream cis = new CipherInputStream(infile, cipher);
            doCopy(cis, outfile);
            System.out.println("File encrypted to \"" + os + "\"");
        } else if (mode == Cipher.DECRYPT_MODE) {
            cipher.init(Cipher.DECRYPT_MODE, key);
            CipherOutputStream cos = new CipherOutputStream(outfile, cipher);
            doCopy(infile, cos);
            System.out.println("File decrypted to \"" + os + "\"");
        }
    }

    private static SecretKey loadSecret(String keystore, String password) {
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
            System.out.println("Erro no load da chave secreta!\n");
        }
        return null;
    }

    private static void generateKey(String keystore, String password) {
        try {
            SecretKey sk = KeyGenerator.getInstance("RC4").generateKey();
            KeyStore ks = getInstance("JCEKS");
            File f = new File(keystore);

            if (f.exists()) {
                ks.load(new FileInputStream(f), password.toCharArray());
            } else {
                ks.load(null, null);
                ks.store(new FileOutputStream(f), password.toCharArray());
            }
            SecretKeyEntry se = new SecretKeyEntry(sk);
            PasswordProtection ps = new PasswordProtection(password.toCharArray());
            ks.setEntry("SecretKey", se, ps);
            ks.store(new FileOutputStream(f), password.toCharArray());
        } catch (CertificateException | NoSuchAlgorithmException | IOException | KeyStoreException e) {
            System.out.println("Erro na geração da chave secreta!\n");
        }
    }

    public static void doCopy(InputStream is, OutputStream os) throws IOException {
        byte[] bytes = new byte[64];
        int numBytes;
        while ((numBytes = is.read(bytes)) != -1) {
            os.write(bytes, 0, numBytes);
        }
        os.flush(); os.close(); is.close();
    }

    private static String readLine() throws IOException {
        BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
        return stdin.readLine();
    }

    private static void PrintMenu() {
        System.out.println("Options:\n" +
                "\t-genkey <keyfile> <pass>\n" +
                "\t-enc <keyfile> <pass> <inputfile> <outputfile>\n" +
                "\t-dec <keyfile> <pass> <inputfile> <outputfile>\n" +
                "\t:quit\n");
    }

    public static void main(String[] s)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        Boolean flag = true;

        while (flag) {
            PrintMenu();
            String line = readLine();

            String[] args = line.split(" ");
            if ((args.length == 5 || args.length != 2) && !args[0].equals(":quit")) {
                switch (args[0]) {
                    case "-genkey":
                        if (args.length == 3) {
                            generateKey(args[1], args[2]);
                        } else {
                            System.out.println("Insufficient arguments!");
                        }
                        break;
                    case "-enc":
                        if (args.length == 5) {
                            encrypt(args[1], args[2], args[3], args[4]);
                        } else {
                            System.out.println("Insufficient arguments!");
                        }
                        break;
                    case "-dec":
                        if (args.length == 5) {
                            decrypt(args[1], args[2], args[3], args[4]);
                        } else {
                            System.out.println("Insufficient arguments!");
                        }
                        break;
                    default:
                        System.out.println("Command not found!");
                }
            } else if (args[0].equals(":quit")) {
                flag = false;
                System.out.println("Goodbye!");
            } else {
                System.out.println("Insufficient arguments!");
            }
        }
    }
}
