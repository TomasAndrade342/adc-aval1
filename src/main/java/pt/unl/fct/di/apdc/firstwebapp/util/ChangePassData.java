package pt.unl.fct.di.apdc.firstwebapp.util;

public class ChangePassData {
    public String userName;
    public String password;
    public String newPassword;
    public String newPasswordAgain;

    public ChangePassData() {

    }

    public ChangePassData(String userName, String password, String newPassword, String newPasswordAgain) {
        this.userName = userName;
        this.password = password;
        this.newPassword = newPassword;
        this.newPasswordAgain = newPasswordAgain;
    }
}
