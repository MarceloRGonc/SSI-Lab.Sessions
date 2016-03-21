import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collections;

/**
 * Created by MGonc on 17/03/16.
 */
public class CertValidator {

    public static void main(String[] args) {
        PrivateKey c = getPrivateKey("Cliente.p12","Cliente1");
        PrivateKey s = getPrivateKey("Servidor.p12","Servidor");
        X509Certificate ca = getCertificate("CA.cer");
        CertPath c3a = getCertificate("Servidor.p12", "Servidor");

        if(c != null && s != null && ca != null){
            validateCert(ca, c3a);
            System.out.println("Size: " + c3a.toString());

        } else {
            System.out.println("Something went wrong!");
        }
    }

    public static PrivateKey getPrivateKey(String keystore, String alias) {
        try {
            File f = new File(keystore);
            KeyStore ks = KeyStore.getInstance("PKCS12");

            if (f.exists()) {
                ks.load(new FileInputStream(f), "1234".toCharArray());
            } else { return null; }

            PrivateKey privkey = (PrivateKey) ks.getKey(alias, "1234".toCharArray());
            return privkey;
        } catch (CertificateException | NoSuchAlgorithmException | IOException
                | UnrecoverableEntryException | KeyStoreException e) {
            System.out.println("Error loading KeyStore: " + keystore + "! " + e + "\n");
            return null;
        }
    }

    public static CertPath getCertificate(String filename, String alias) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            File f = new File(filename);

            if (f.exists()) {
                ks.load(new FileInputStream(f), "1234".toCharArray());
            } else { return null; }

            Certificate[] certArray = ks.getCertificateChain(alias);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            CertPath certPath = certFactory.generateCertPath(Arrays.asList(certArray));
            return certPath;
        } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException
                | IOException e) {
            System.out.println("Error loading Certificate: " + filename + "! " + e + "\n");
        }
        return null;
    }

    public static X509Certificate getCertificate(String filename) {
        X509Certificate cert = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf
                    .generateCertificate(new FileInputStream(filename));
        } catch (IOException | CertificateException e) {
            System.out.println("Error loading Certificate: " + filename + "! " + e + "\n");
        }
        return cert;
    }

    public static boolean validateCert(X509Certificate caCert, CertPath certPath) {
        CertPathValidator cpv = null;
        boolean res = false;
        try {
            cpv = CertPathValidator.getInstance("PKIX");
            // TrustAnchor representa os pressupostos de confiança que se aceita como válidos
            // (neste caso, unicamente a CA que emitiu os certificados)
            TrustAnchor anchor = new TrustAnchor(caCert, null);
            // Podemos também configurar o próprio processo de validação
            // (e.g. requerer a presença de determinada extensão).
            PKIXParameters params = null;
            params = new PKIXParameters(Collections.singleton(anchor));
            // ...no nosso caso, vamos simplesmente desactivar a verificação das CRLs
            params.setRevocationEnabled(false);
            // Finalmente a validação propriamente dita...
            CertPathValidatorResult cpvResult = cpv.validate(certPath, params);
            res = true;
        } catch (InvalidAlgorithmParameterException iape) {
            System.err.println("Erro de validação: " + iape);
        } catch (CertPathValidatorException | NoSuchAlgorithmException cpve) {
            System.err.println("Erro de validação: " + cpve);
        }
        return res;
    }
}

