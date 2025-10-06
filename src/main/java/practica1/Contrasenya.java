package practica1;

import java.util.Base64;

public class Contrasenya {

    private String hash;
    private String salt;

    public Contrasenya(String hash, String salt){
        this.hash = hash;
        this.salt = salt;
    }

    public Contrasenya(byte[] hash, byte[] salt){
        this.hash = Base64.getEncoder().encodeToString(hash);
        this.salt = Base64.getEncoder().encodeToString(salt);
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
