package practica1;

import java.util.Base64;

public class Usuari {

    private String user;
    private String hash;
    private String salt;


    public Usuari(String user, String hash, String salt){
        this.user = user;
        this.hash = hash;
        this.salt = salt;
    }

    public Usuari(String user, byte[] hash, String salt) {
        this.user = user;
        this.hash = Base64.getEncoder().encodeToString(hash);
        this.salt = salt;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
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

    @Override
    public String toString() {
        return "Usuari{" +
                "user='" + user + '\'' +
                ", hash='" + hash + '\'' +
                ", salt='" + salt + '\'' +
                '}';
    }
}
