package pt.unl.fct.di.apdc.firstwebapp.util;

public class StateData {
    public String targetUserName;
    public String userName;
    public String state;

    public StateData() {

    }

    public StateData(String targetUserName, String userName, String state) {
        this.targetUserName = targetUserName;
        this.userName = userName;
        this.state = state;
    }
}
