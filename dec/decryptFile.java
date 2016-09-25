public class decryptFile{

    private static final String MAP = "SHA1";
    private static final String ENCRYPTION_METHOD = "AES";
    private static final String MAP_IDENTIFIER = "SSSHHHAAA111";

    public static void main (String args[]){
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

        //create key using user input as seed
        byte[] rawKey = createKey(seed.getBytes());
        SecretKeySpec key = new SecretKeySpec(rawKey, ENCRYPTION_METHOD);

        byte[] plaintext = decyrpt(key);

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

    public static byte[] createKey(byte[] seed){
        byte[] raw = {};

        try{
            //use user input as seed for generating random key
            SecureRandom random = new SecureRandom(seed);
            KeyGenerator keyGen = KeyGenerator.getInstance(ENCRYPTION_METHOD);
            keyGen.init(random);
            raw = keyGen.generateKey().getEncoded();

        }catch(NoSuchAlgorithmException e){
            System.out.println("Error creating secret key");
        }

        return raw;
    }

    public static byte[] decrypt(SecretKey key){
        byte[] plaintext = {};

        //encrypt data
        try{
            Cipher genCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            genCipher.init(Cipher.DECRYPT_MODE, key);
            cipherText = genCipher.doFinal(data_md);
        }catch(GeneralSecurityException e){
            System.out.println("Error encountered during encryption.");
        }

        return plaintext;
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

    public static byte[] checkIntegrity(byte[] file){
        boolean identFound = false;
        int index = -1;

        //convert MAP identifier from string to byte[]
        byte[] byteMAPIdentifier = MAP_IDENTIFIER.getBytes();

        for (int i=0; i < file.length; i++){
            for (int j = i; j < i + byteMAPIdentifier.length && i+byteMAPIdentifier.length < file.length; j++){
                if (file[j] != byteMAPIdentifier[j-i]){
                    break;
                } else if (j-i == byteMAPIdentifier.length){
                    identFound = true;
                    index = i;
                }
            }

            if (identFound) break;
        }

        if (!identFound) return new byte[0];

        //split file into data and md
        byte[] data = new data[index+1];
        System.arraycopy(file, 0, data, 0, data.length);

        byte[] fileDigest = new byte[file.length-index-byteMAPIdentifier.length];
        System.arraycopy(fileDigest,index + byteMAPIdentifier.length, fileDigest, fileDigest.length);

        //create md from data and compare with md appended to file
        byte[] genDigest = createDigest(data);

        if(Arrays.equals(fileDigest, genDigest)){
            return data;
        }

        return new byte[0];

    }
}