import javax.crypto.spec.*;
import java.io.*;

public class decryptFile extends Utils{

    private static final String MAP = "SHA1";
    private static final String ENCRYPTION_METHOD = "AES";

    public static void main(String args[]){
        String file = "", seed = "";
        byte[] data = {}, digest = {}, rawKey = {}, pText = {};

        if (args.length != 2){
            System.out.println("Run program by invoking the command \'java decryptFile [plaintext-filename] [seed]\' ");
            System.exit(0);
        }else{
            file = args[0];
            seed = args[1];
        }

        //read file into byte array
        readFile(file, data);

        try{
            //create key using user input as seed
            rawKey = makeKey(seed.getBytes("UTF-8"), ENCRYPTION_METHOD);
            SecretKeySpec key = new SecretKeySpec(rawKey, ENCRYPTION_METHOD);

            //encrypt data and write te file
            decrypt(data, digest, key, pText);

            //create message digest
            makeDigest(data,digest, MAP);

            //write encrypted data to file
            FileOutputStream pFile = new FileOutputStream("decrypted-" + file);
            pFile.write(pText);
            pFile.close();

        }catch(IOException e){
            System.out.println("An error was encountered during decryption.");
        }

    }
}