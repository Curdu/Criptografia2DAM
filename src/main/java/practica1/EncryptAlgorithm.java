package practica1;

/// Llistat de algoritmes d'encriptació suportats per java. Font: [KeyGeneratorAlgorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyGenerator)
public enum EncryptAlgorithm {

    AES("AES", 128),
    DES("DES", 56),
    DESEDE("DESede", 168),
    ARCFOUR("ARCFOUR", 128),
    BLOWFISH("Blowfish", 128),
    CHACHA20("ChaCha20", 256),
    RC2("RC2", 128),
    HMAC_MD5("HmacMD5", 128),
    HMAC_SHA1("HmacSHA1", 160),
    HMAC_SHA224("HmacSHA224", 224),
    HMAC_SHA256("HmacSHA256", 256),
    HMAC_SHA384("HmacSHA384", 384),
    HMAC_SHA512("HmacSHA512", 512),
    HMAC_SHA3_224("HmacSHA3-224", 224),
    HMAC_SHA3_256("HmacSHA3-256", 256),
    HMAC_SHA3_384("HmacSHA3-384", 384),
    HMAC_SHA3_512("HmacSHA3-512", 512);

    private final String algoritme;
    private final int midaRecomanda;

    EncryptAlgorithm(String algoritme,int midaRecomenada) {
        this.algoritme = algoritme;
        this.midaRecomanda = midaRecomenada;
    }

    public int getMidaRecomanda() {
        return midaRecomanda;
    }

    public String getAlgoritme() {
        return algoritme;
    }
}
