package pt.unl.fct.di.apdc.firstwebapp.util;

import com.google.cloud.datastore.Entity;

public class JsonUser {
    public String email;
    public String userName;
    public String fullName;
    public String phoneNum;
    public String password;
    public boolean isPublic;
    public String ccNum;
    public String role;
    public String nif;
    public String employer;
    public String function;
    public String address;
    public String employerNif;
    public String accountState;

    public JsonUser() {

    }

    public JsonUser(String email, String userName, String fullName, String phoneNum, String password,
                    boolean isPublic, String ccNum, String role, String nif, String employer, String function,
                    String address, String employerNif, String accountState) {
        this.email = email;
        this.userName = userName;
        this.fullName = fullName;
        this.phoneNum = phoneNum;
        this.password = password;
        this.isPublic = isPublic;
        this.ccNum = ccNum;
        this.role = role;
        this.nif = nif;
        this.employer = employer;
        this.function = function;
        this.address = address;
        this.employerNif = employerNif;
        this.accountState = accountState;
    }

    public JsonUser(Entity userEntity) {
        this.email = userEntity.getString("email");
        this.userName = userEntity.getString("userName");
        this.fullName = userEntity.getString("fullName");
        this.phoneNum = userEntity.getString("phoneNum");
        this.password = userEntity.getString("password"); // careful: already hashed!
        this.isPublic = userEntity.getBoolean("isPublic");
        this.ccNum = userEntity.contains("ccNum") ? userEntity.getString("ccNum") : "NOT DEFINED";
        this.role = userEntity.getString("role");
        this.nif = userEntity.contains("nif") ? userEntity.getString("nif") : "NOT DEFINED";
        this.employer = userEntity.contains("employer") ? userEntity.getString("employer") : null;
        this.function = userEntity.contains("function") ? userEntity.getString("function") : null;
        this.address = userEntity.contains("address") ? userEntity.getString("address") : null;
        this.employerNif = userEntity.contains("employerNif") ? userEntity.getString("employerNif") : "NOT DEFINED";
        this.accountState = userEntity.getString("accountState");
    }
}
