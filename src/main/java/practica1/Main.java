package practica1;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.sql.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

public class Main {

    public static void main(String[] args) {


//        System.out.println(getSimetricKey(EncryptAlgorithm.DES));


//        System.out.println(digestName("Jordi Cordomí Raset",MessageDigestAlgorithm.SHA_512));
//        System.out.println(digestNameAmbSalt("Jordi Cordomí Raset", MessageDigestAlgorithm.SHA_512));
//        System.out.println(digestNameAmbSalt("Jordi Cordomí Raset", MessageDigestAlgorithm.SHA_512));
//        guardarContrasenya("cafe");
//        System.out.println(digestAndEncrypt("Cafe"));
//
//        System.out.println(iniciarSessio("curdu","admin"));
//        KeyPair keyPair = getClausAsimetriques(2048, KeyPairGeneratorAlgorithm.RSA);
//        PrivateKey prk = keyPair.getPrivate();
//        PublicKey puk = keyPair.getPublic();
//
//        System.out.println("Clau priv: " + Base64.getEncoder().encodeToString(prk.getEncoded()));
//        System.out.println("Clau pub: " + Base64.getEncoder().encodeToString(puk.getEncoded()));
////
//        System.out.println(Arrays.toString(encryptPasswd("admin", prk)));
//        System.out.println(Base64.getEncoder().encodeToString(decryptPasswd(digestAndEncryptPasswd("admin",prk),puk)));
//        mostrarClau("C:\\Users\\curdu\\IdeaProjects\\DAM2\\Criptografia\\clauRSA2.jks","clauRSA2");
        crearEmmagatzemarSimetricKey("Cafe", "CafeRSA.jks","admin123","admin123");
        mostrarClau("CafeRSA.jks","Cafe");




    }


    private static String getSimetricKey(EncryptAlgorithm algorithm){

        try{
            KeyGenerator keygen = KeyGenerator.getInstance(algorithm.getAlgoritme());
            keygen.init(algorithm.getMidaRecomanda());
            SecretKey sKey = keygen.generateKey();
            return Base64.getEncoder().encodeToString(sKey.getEncoded());
        }catch (NoSuchAlgorithmException e){
            System.out.println("Algoritme inexistent: " + e.getLocalizedMessage());
        }
        return null;

    }


    private static String digestName(String message , MessageDigestAlgorithm algorithm){

        try{
            MessageDigest md = MessageDigest.getInstance(algorithm.getAlgoritme());
            byte[] digestedMessage = md.digest(message.getBytes());
            return Base64.getEncoder().encodeToString(digestedMessage);


        }catch (NoSuchAlgorithmException e) {
            System.out.println("Algoritme inexistent: " + e.getLocalizedMessage());
        }
        return null;

    }

    private static String digestAndEncrypt(String text){
        try {
            MessageDigest md = MessageDigest.getInstance(MessageDigestAlgorithm.SHA_256.getAlgoritme());
            byte[] hash = md.digest(text.getBytes());

            SecretKeySpec clauAES = new SecretKeySpec(hash,"AES");

            return HexFormat.of().formatHex(clauAES.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    private static String digestNameAmbSalt(String message, MessageDigestAlgorithm algorithm){

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[64];
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(algorithm.getAlgoritme());
            random.nextBytes(salt);
            md.update(salt);
            return Base64.getEncoder().encodeToString(md.digest(message.getBytes()));

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Algoritme inexistent: " + e.getLocalizedMessage());
        }
        return null;

    }

    private static void guardarContrasenya(String passwd){
        Contrasenya contrasenya = crearContrasenyaInstance(passwd);

        try {
            
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/criptojordicordomi","curdu","admin");
            String sql = "INSERT INTO contrasenyes (hash,salt) VALUES (?,?)";
            PreparedStatement prepStat = conn.prepareStatement(sql);
            prepStat.setString(1,contrasenya.getHash());
            prepStat.setString(2,contrasenya.getSalt());
            prepStat.execute();
            System.out.println("Contrasenya guardada correctament");

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }

    }

    private static Contrasenya crearContrasenyaInstance(String contrasenya) {

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(MessageDigestAlgorithm.SHA_512.getAlgoritme());
            random.nextBytes(salt);
            md.update(salt);
            byte[] hash = md.digest(contrasenya.getBytes());
            return new Contrasenya(hash,salt);

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Algoritme inexistent: " + e.getLocalizedMessage());
        }
        return null;
    }

    private static Usuari crearUsuariInstance(String user, String passwd) {
        SecureRandom random = new SecureRandom();
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(MessageDigestAlgorithm.SHA_512.getAlgoritme());
            int saltEnter = random.nextInt();
            String salt = Integer.toHexString(saltEnter);
            md.update(salt.getBytes());
            byte[] hash = md.digest(passwd.getBytes());
            return new Usuari(user,hash,salt);

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Algoritme inexistent: " + e.getLocalizedMessage());
        }
        return null;
    }

    private static void guardarUsuari(String user, String passwd) {
        Usuari usuari = crearUsuariInstance(user,passwd);

        try {

            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/criptojordicordomi","curdu","admin");
            String sql = "INSERT INTO usuaris (hash,salt,user) VALUES (?,?,?)";
            PreparedStatement prepStat = conn.prepareStatement(sql);
            prepStat.setString(1,usuari.getHash());
            prepStat.setString(2,usuari.getSalt());
            prepStat.setString(3,usuari.getUser());
            prepStat.execute();
            System.out.println("Usuari guardada correctament");

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean iniciarSessio(String user, String passwd){
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/criptojordicordomi","curdu","admin");
            MessageDigest md = MessageDigest.getInstance(MessageDigestAlgorithm.SHA_512.getAlgoritme());
            PreparedStatement selectStatement = conn.prepareStatement("SELECT hash,salt FROM usuaris WHERE usuaris.user=? ");
            selectStatement.setString(1,user);
            ResultSet resultSet = selectStatement.executeQuery();
            while (resultSet.next()){
                String hash = resultSet.getString("hash");
                String salt = resultSet.getString("salt");

                md.update(salt.getBytes());

                return hash.equals(Base64.getEncoder().encodeToString(md.digest(passwd.getBytes())));
            }

            return false;
        } catch (SQLException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    private static KeyPair getClausAsimetriques(int len, KeyPairGeneratorAlgorithm algorithm){
        KeyPair keys = null;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm.getAlgorithm());
            keyPairGenerator.initialize(len);
            keys = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return keys;
    }

    private static byte[] encryptPasswd(String passwd, PrivateKey privKey){
        byte[] encryptedPasswd = null;

        try {
            Cipher xifrador = Cipher.getInstance(KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
            xifrador.init(Cipher.ENCRYPT_MODE, privKey);
            encryptedPasswd = xifrador.doFinal(passwd.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
        return encryptedPasswd;

    }

    private static byte[] digestAndEncryptPasswd(String passwd, PrivateKey privateKey){
        String hash = digestName(passwd, MessageDigestAlgorithm.SHA_512);
        return encryptPasswd(hash, privateKey);

    }

    private static byte[] decryptPasswd(byte[] encryptedPasswd, PublicKey pubKey){
        byte[] decryptedPasswd = null;

        try {
            Cipher xifrador = Cipher.getInstance(KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
            xifrador.init(Cipher.DECRYPT_MODE, pubKey);
            decryptedPasswd = xifrador.doFinal(encryptedPasswd);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }

        return decryptedPasswd;
    }

    private static void mostrarClau(String path, String alias) {
        try {
            KeyStore ks = KeyStore.getInstance("JCEKS");
            File file = new File(path);
            if(file.isFile()){
                FileInputStream fInStream =  new FileInputStream(file);
                ks.load(fInStream,"admin123".toCharArray());
                Key k = ks.getKey(alias,"admin123".toCharArray());
                System.out.println(Base64.getEncoder().encodeToString(k.getEncoded()));
            }
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException |
                 UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static void crearEmmagatzemarSimetricKey(String alias,String keystorePath, String storePassword, String keyPassword){

        KeyGenerator keygen = null;
        try {
            keygen = KeyGenerator.getInstance(EncryptAlgorithm.AES.getAlgoritme());
            keygen.init(EncryptAlgorithm.AES.getMidaRecomanda());
            SecretKey sKey = keygen.generateKey();
            KeyStore ks = KeyStore.getInstance("JCEKS");
            java.io.File ksFile = new java.io.File(keystorePath);
            if (ksFile.exists()) {
                try (java.io.FileInputStream fis = new java.io.FileInputStream(ksFile)) {
                    ks.load(fis, storePassword.toCharArray());
                }

            }else {
                ks.load(null, null);
            }
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(keyPassword.toCharArray());
            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(sKey);
            ks.setEntry(alias, skEntry, protParam);
            try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
                ks.store(fos, storePassword.toCharArray());
            }

            System.out.println("Clau guardada al keystore: " + keystorePath + " amb alias: " + alias);

        } catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | IOException e) {
            throw new RuntimeException(e);
        }
    }

}
