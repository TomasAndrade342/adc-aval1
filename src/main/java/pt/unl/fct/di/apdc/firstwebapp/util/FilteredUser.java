package pt.unl.fct.di.apdc.firstwebapp.util;

public class FilteredUser {
    public String userName;
    public String email;
    public String fullName;

    public FilteredUser() {

    }

    public FilteredUser(String userName, String email, String fullName) {
        this.userName = userName;
        this.email = email;
        this.fullName = fullName;
    }
}
