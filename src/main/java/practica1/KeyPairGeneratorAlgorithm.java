package practica1;

/// Llistat de algoritmes d'encriptació per a KeyPairGenerator. Font: [KeyPairGeneratorAlgorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator)
public enum KeyPairGeneratorAlgorithm {

    DIFFIE_HELLMAN("DH"),
    DSA("DSA"),
    RSA("RSA"),
    RSASSA_PSS("RSASSA-PSS"),
    EC("EC");

    private final String algorithm;

    KeyPairGeneratorAlgorithm(String algorithm){
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        return algorithm;
    }
}
