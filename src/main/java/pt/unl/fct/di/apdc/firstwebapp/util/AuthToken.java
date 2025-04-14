package pt.unl.fct.di.apdc.firstwebapp.util;

import java.util.UUID;

public class AuthToken {

    public static final long EXPIRATION_TIME = 1000*60*60*2;

    public String userName;
    public String role;
    public long creationDate;
    public long expirationDate;
    public String magicVal;

    public AuthToken() {

    }

    public AuthToken(String userName, String role) {
        this.userName = userName;
        this.role = role;
        this.creationDate = System.currentTimeMillis();
        this.expirationDate = this.creationDate + EXPIRATION_TIME;
        this.magicVal = UUID.randomUUID().toString();
    }
}
