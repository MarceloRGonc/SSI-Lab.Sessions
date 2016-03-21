
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.security.*;

/**
 * Created by MGonc on 07/03/16.
 */
public class KGenerator {

    /** Fixed Parameters */
    private static final BigInteger p = new BigInteger("9949409665013933710618693397761851397414627483156676817" +
            "9581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382" +
            "4453234999316254512726001731801361232454412041335158004959172420118635587217233036615233725" +
            "72477211620144038809673692512025566673746993593384600667047373692203583");

    private static final BigInteger g = new BigInteger("4415740483796032876887268067768680265099916322676669479" +
           "7650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974" +
            "3149350155015713330247731724403524753587506682134446073538727546508050319128666921198193770" +
            "41901642732455911509867728218394542745330014071040326856846990119719675");

    public static KeyPair keyGeneratorDH() {

        KeyPairGenerator kpg = null;
        DHParameterSpec dhSpec = null;

        try {
            AlgorithmParameterGenerator apGen = AlgorithmParameterGenerator.getInstance("DH");
            apGen.init(1024);
            dhSpec = new DHParameterSpec(p, g);
            kpg = KeyPairGenerator.getInstance("DH");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error KeyPairGenerator! - NoSuchAlgorithmException");
        }

        if(kpg != null && dhSpec != null) {
            try {
                /** Initialize KeyPairGenerator */
                kpg.initialize(dhSpec);

                /** Generate key pair */
                return kpg.generateKeyPair();

            } catch (InvalidAlgorithmParameterException e) {
                System.out.println("Error initialize pair! - InvalidAlgorithmParameterException");
            }
        }
        return null;
    }
}
