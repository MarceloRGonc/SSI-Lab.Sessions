import java.net.*;

/**
 * Created by MGonc on 29/02/16.
 */
public class Servidor {

    private static int tcount;

    public static void main(String []args) {
        tcount = 0;
        try {
            ServerSocket ss = new ServerSocket(4567);

            while(true) {
                Socket s = ss.accept();
                tcount++;
                TServidor ts = new TServidor(s,tcount);
                ts.start();
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}
