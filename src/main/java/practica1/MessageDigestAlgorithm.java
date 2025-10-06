package practica1;

/// Llistat de algoritmes de hash acceptats en java. Font: [Message Digest Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#MessageDigest)
public enum MessageDigestAlgorithm {
    MD2("MD2"),
    MD5("MD5"),
    SHA_1("SHA-1"),
    SHA_224("SHA-224"),
    SHA_256("SHA-256"),
    SHA_384("SHA-384"),
    SHA_512("SHA-512");

    private final String algoritme;

    MessageDigestAlgorithm(String algoritme) {
        this.algoritme = algoritme;
    }

    public String getAlgoritme() {
        return algoritme;
    }
}
