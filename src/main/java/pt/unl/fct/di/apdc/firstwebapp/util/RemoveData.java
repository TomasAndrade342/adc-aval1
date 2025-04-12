package pt.unl.fct.di.apdc.firstwebapp.util;

public class RemoveData {

    public String targetUserName;
    public String userName;
    public String email;

    public RemoveData() {

    }

    public RemoveData(String targetUserName, String userName, String email) {
        this.targetUserName = targetUserName;
        this.userName = userName;
        this.email = email;
    }
}
