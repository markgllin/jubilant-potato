import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.io.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.*;

import java.security.*;

abstract public class Utils{

    public static void readFile(String file, byte[] data){
        try{
            //read file in as bytes
            Path path = Paths.get(file);
            data = Files.readAllBytes(path);

        }catch (IOException e){
            System.out.println("Incorrect file path");
        }
    }

    public static void makeDigest(byte[] data, byte[] digest, String msgAuthMethod){
        try{
            //create message digest
            MessageDigest md = MessageDigest.getInstance(msgAuthMethod);
            md.update(data);
            digest = md.digest();

        }catch(NoSuchAlgorithmException e){
            System.out.println("Error creating digest");
        }
    }

    public static byte[] makeKey(byte[] seed, String encMethod){
        byte[] raw = {};

        try{
            //use user input as seed for generating random key
            SecureRandom random = new SecureRandom(seed);
            KeyGenerator keyGen = KeyGenerator.getInstance(encMethod);
            keyGen.init(random);
            raw = keyGen.generateKey().getEncoded();

        }catch(NoSuchAlgorithmException e){
            System.out.println("Error creating secret key");
        }

        return raw;
    }

    public static void encrypt(byte[] data, byte[] md, SecretKey key, byte[] ciphertext){
        //combine data with identifier and MAP
        byte[] data_md = new byte[data.length + md.length];
        System.arraycopy(data, 0, data_md, 0, data.length);
        System.arraycopy(md, 0, data_md, data.length, md.length);
        
        //encrypt data
        try{
            Cipher genCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            genCipher.init(Cipher.ENCRYPT_MODE, key);
            ciphertext = genCipher.doFinal(data_md);
        }catch(GeneralSecurityException e){
            System.out.println("Error encountered during encryption.");
        }
    }

    public static void decrypt(byte[] data, byte[] md, SecretKey key, byte[] plaintext){
        //decrypt data
        try{
            Cipher genCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            genCipher.init(Cipher.DECRYPT_MODE, key);
            plaintext = genCipher.doFinal(data);
            
        }catch(GeneralSecurityException e){
            System.out.println("Error encountered during decryption.");
        }
    }
}