package pt.unl.fct.di.apdc.firstwebapp.util;

public class RoleData {
    public String targetUserName;
    public String userName;
    public String role;

    public RoleData() {

    }

    public RoleData(String targetUserName, String userName, String role) {
        this.targetUserName = targetUserName;
        this.userName = userName;
        this.role = role;
    }
}
