import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.io.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.*;

import java.security.*;

public class secureFile{

    private static final String MAP = "SHA1";
    private static final String ENCRYPTION_METHOD = "AES";

    public static void main(String args[]){
        String file = "", seed = "";
        byte[] data = {}, digest = {}, rawKey = {}, cText = {};

        if (args.length != 2){
            System.out.println("Run program by invoking the command \'java secureFile [plaintext-filename] [seed]\' ");
            System.exit(0);
        }else{
            file = args[0];
            seed = args[1];
        }

        //read file into byte array
        data = readFile(file);

        //create message digest
        digest = makeDigest(data);

        try{
            //create key using user input as seed
            rawKey = makeKey(seed.getBytes("UTF-8"));
            SecretKeySpec key = new SecretKeySpec(rawKey, ENCRYPTION_METHOD);

            //encrypt data and write te file
            cText = encrypt(data, digest, key);

            //write encrypted data to file
            FileOutputStream cFile = new FileOutputStream("/home/mark/Documents/CPSC418-JCA/dec/encrypted");
            cFile.write(cText);
            cFile.close();

        }catch(IOException e){
            System.out.println("An error was encountered during encryption.");
        }

    }

    public static byte[] readFile(String file){
        byte[] data = {};

        try{
            //read file in as bytes
            Path path = Paths.get(file);
            data = Files.readAllBytes(path);
        }catch (IOException e){
            System.out.println("Incorrect file path");
        }

        return data;
    }

    public static byte[] makeDigest(byte[] data){
        byte[] digest = {};

        try{
            //create message digest
            MessageDigest md = MessageDigest.getInstance(MAP);
            md.update(data);
            digest = md.digest();
        }catch(NoSuchAlgorithmException e){
            System.out.println("Error creating digest");
        }

        return digest;
    }

    public static byte[] makeKey(byte[] seed){
        byte[] raw = {};

        try{
            //use user input as seed for generating random key
            SecureRandom random = new SecureRandom("SHA1PRNG");
            random.setSeed(seed);
            KeyGenerator keyGen = KeyGenerator.getInstance(ENCRYPTION_METHOD);
            keyGen.init(128, random);
            raw = keyGen.generateKey().getEncoded();

        }catch(NoSuchAlgorithmException e){
            System.out.println("Error creating secret key");
        }

        return raw;
    }

    public static byte[] encrypt(byte[] data, byte[] md, SecretKey key){
        byte[] ciphertext = {};

        //combine data with identifier and MAP
        byte[] data_md = new byte[data.length + md.length];
        System.arraycopy(data, 0, data_md, 0, data.length);
        System.arraycopy(md, 0, data_md, data.length, md.length);
        
        //encrypt data
        try{
            Cipher genCipher = Cipher.getInstance("AES");
            genCipher.init(Cipher.ENCRYPT_MODE, key);
            ciphertext = genCipher.doFinal(data_md);
        }catch(GeneralSecurityException e){
            System.out.println("Error encountered during encryption.");
        }

        return ciphertext;
    }

}
