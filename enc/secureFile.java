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
    private static final String MAP_IDENTIFIER = "SSSHHHAAA111";

    public static void main(String args[]){
        String file = "";
        String seed = "";

        if (args.length != 2){
            System.out.println("Run program by invoking the command \'java secureFile [plaintext-filename] [seed]\' ");
            System.exit(0);
        }else{
            file = args[0];
            seed = args[1];
        }

        //read file into byte array
        byte[] data = fileToBytes(file);

        //create message digest
        byte[] digest = createDigest(data);

        //create key using user input as seed
        byte[] rawKey = createKey(seed.getBytes());
        SecretKeySpec key = new SecretKeySpec(rawKey, ENCRYPTION_METHOD);

        //encrypt data and write te file
        byte[] ciphertext = encrypt(data, digest, key);

        try{
            FileOutputStream cipherTextFile = new FileOutputStream("encrypted-" + file);
            cipherTextFile.write(ciphertext);
            cipherTextFile.close();
        }catch(IOException e){
            System.out.println("Invalid filepath or name entered.");
        }

    }

    public static byte[] fileToBytes(String file){
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

    public static byte[] createDigest(byte[] data){
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

    public static byte[] createKey(byte[] seed){
        byte[] raw = {};

        try{
            //use use input as seed for generating random key
            SecureRandom random = new SecureRandom(seed);
            KeyGenerator keyGen = KeyGenerator.getInstance(ENCRYPTION_METHOD);
            keyGen.init(random);
            raw = keyGen.generateKey().getEncoded();

        }catch(NoSuchAlgorithmException e){
            System.out.println("Error creating secret key");
        }

        return raw;
    }

    public static byte[] encrypt(byte[] data, byte[] md, SecretKey key){
        byte[] cipherText = {};

        //convert MAP identifier from string to byte[]
        byte[] byteMAPIdentifier = MAP_IDENTIFIER.getBytes();

        //combine data with identifier and MAP
        byte[] data_md = new byte[data.length + md.length + byteMAPIdentifier.length];
        System.arraycopy(data, 0, data_md, 0, data.length);
        System.arraycopy(byteMAPIdentifier,0,data_md,data.length,byteMAPIdentifier.length);
        System.arraycopy(md, 0, data_md, data.length + byteMAPIdentifier.length, md.length);
        
        //encrypt data
        try{
            Cipher genCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            genCipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = genCipher.doFinal(data_md);
        }catch(GeneralSecurityException e){
            System.out.println("Error encountered during encryption.");
        }

        return cipherText;
    }

}
