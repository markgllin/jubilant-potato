import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.io.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.*;

import java.security.*;

public class decryptFile{

    private static final String MAP = "SHA1";
    private static final String ENCRYPTION_METHOD = "AES";

    public static void main(String args[]){
        String file = "", seed = "";
        byte[] data = {}, digest = {}, rawKey = {}, pText = {}, decrypted = {};
        byte[] file_Digest = new byte[20];
        byte[] fData;

        if (args.length != 2){
            System.out.println("Run program by invoking the command \'java secureFile [plaintext-filename] [seed]\' ");
            System.exit(0);
        }else{
            file = args[0];
            seed = args[1];
        }


        //read file into byte array
        data = readFile(file);

        try{
            //create key using user input as seed
            rawKey = makeKey(seed.getBytes("UTF-8"));
            SecretKeySpec key = new SecretKeySpec(rawKey, ENCRYPTION_METHOD);

            //encrypt data and write to file
            decrypted = decrypt(data, digest, key);

            //get digest from data
            fData = new byte[decrypted.length-20];
            System.arraycopy(decrypted, 0, fData, 0, fData.length);
            System.arraycopy(decrypted, decrypted.length - 20, file_Digest, 0, 20);

            //create message digest
            digest = makeDigest(fData);

            if (!MessageDigest.isEqual(digest, file_Digest)){
                System.out.println("File has been modified.")
            }

            //write encrypted data to file
            FileOutputStream pFile = new FileOutputStream("decrypted.png");
            pFile.write(fData);
            pFile.close();

        }catch(IOException e){
            System.out.println("An error was encountered during encryption.");
            e.printStackTrace();
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
            System.exit(0);
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
            SecureRandom random = new SecureRandom(seed);
            KeyGenerator keyGen = KeyGenerator.getInstance(ENCRYPTION_METHOD);
            keyGen.init(128, random);
            raw = keyGen.generateKey().getEncoded();

        }catch(NoSuchAlgorithmException e){
            System.out.println("Error creating secret key");
        }

        return raw;
    }

    public static byte[] decrypt(byte[] data, byte[] md, SecretKey key){
        byte[] plaintext = {};

        //decrypt data
        try{
            Cipher genCipher = Cipher.getInstance("AES");
            genCipher.init(Cipher.DECRYPT_MODE, key);
            plaintext = genCipher.doFinal(data);
            
        }catch(GeneralSecurityException e){
            System.out.println("Error encountered during decryption.");
            e.printStackTrace();
        }

        return plaintext;
    }
}