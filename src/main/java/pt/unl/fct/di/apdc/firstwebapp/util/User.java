package pt.unl.fct.di.apdc.firstwebapp.util;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class User {
    public String email;
    public String userName;
    public String fullName;
    public String phoneNum;
    public String password;
    public boolean isPublic;
    public String ccNum;
    public String role;
    public int nif;
    public String employer;
    public String function;
    public String address;
    public int employerNif;
    public String accountState;

    private static final String ALLOWED_PASSWORD_SPECIAL_CHARS = "!#$%&'*+-/=?^_`{|}~";
    private static final Set<String> ALLOWED_USER_ROLES = new HashSet<>(Arrays.asList("ENDUSER", "BACKOFFICE", "ADMIN", "PARTNER"));
    private static final Set<String> ALLOWED_ACCOUNT_STATES = new HashSet<>(Arrays.asList("ACTIVE", "SUSPENDED", "DEACTIVATED"));

    public User() {

    }


    public User(String email, String userName, String fullName, String phoneNum, String password,
                boolean isPublic, String ccNum, String role, int nif, String employer, String function,
                String address, int employerNif, String accountState) {
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

    private boolean nonEmptyOrBlankField(String field) {
        return field != null && !field.isBlank();
    }

    private boolean isValidEmail() {
        if (!nonEmptyOrBlankField(email)) return false;
        String[] parts = email.split("@");
        if (parts.length == 2 && !parts[0].isBlank() && !parts[1].isBlank()) {
            String domain = parts[1];
            return domain.contains(".");
        }
        return false;
    }

    private boolean isPunctuation(char ch) {
        return ALLOWED_PASSWORD_SPECIAL_CHARS.indexOf(ch) >= 0;
    }

    private boolean isValidPassword() {
        if (!nonEmptyOrBlankField(password)) return false;

        boolean hasLower = false;
        boolean hasUpper = false;
        boolean hasDigit = false;
        boolean hasPunctuation = false;

        for (char ch : password.toCharArray()) {
            if (Character.isLowerCase(ch)) hasLower = true;
            else if (Character.isUpperCase(ch)) hasUpper = true;
            else if (Character.isDigit(ch)) hasDigit = true;
            else if (isPunctuation(ch)) hasPunctuation = true;
            if (hasLower && hasUpper && hasDigit && hasPunctuation) {
                return true;
            }
        }
        return false;
    }

    public boolean hasMandatoryFields() {
        return isValidEmail() &&
                nonEmptyOrBlankField(userName) &&
                nonEmptyOrBlankField(fullName) &&
                nonEmptyOrBlankField(phoneNum) && // check if it is supposed to have extension?
                isValidPassword();
    }

    public boolean notBlankIfNotNull(String field) {
        return field == null || !field.isBlank();
    }

    private boolean isValidRole() {
        return ALLOWED_USER_ROLES.contains(role.toUpperCase());
    }

    private boolean isValidState() {
        return ALLOWED_ACCOUNT_STATES.contains(accountState.toUpperCase());
    }

    private boolean isValidNif(int nif) {
        int numDigits = (int) (Math.log10(nif) + 1);
        return nif >= 0 && (nif == 0 || numDigits == 9);
    }

    public boolean fieldsAreValid() {
        return this.email == null || isValidEmail() &&
                notBlankIfNotNull(this.userName) &&
                notBlankIfNotNull(this.fullName) &&
                notBlankIfNotNull(this.phoneNum) &&
                this.password == null || isValidPassword() &&
                optionalFieldsValid();
    }

    public boolean optionalFieldsValid() {
        return notBlankIfNotNull(ccNum) &&
                (notBlankIfNotNull(role) || isValidRole()) &&
                isValidNif(nif) &&
                notBlankIfNotNull(employer) &&
                notBlankIfNotNull(function) &&
                notBlankIfNotNull(address) &&
                isValidNif(employerNif) &&
                (notBlankIfNotNull(accountState) || isValidState());
    }

    public boolean isFullyValid() {
        return hasMandatoryFields() && optionalFieldsValid();
    }

    public Entity asEntity(Key userKey) {
        Entity.Builder builder = Entity.newBuilder(userKey)
                .set("email", this.email)
                .set("userName", this.userName)
                .set("fullName", this.fullName)
                .set("phoneNum", this.phoneNum)
                .set("password", DigestUtils.sha512Hex(this.password))
                .set("isPublic", this.isPublic)
                .set("role", "ENDUSER")
                .set("accountState", "DEACTIVATED");

        if (this.ccNum != null) builder.set("ccNum", this.ccNum);
        if (this.nif != 0) builder.set("nif", this.nif);
        if (this.employer != null) builder.set("employer", this.employer);
        if (this.function != null) builder.set("function", this.function);
        if (this.address != null) builder.set("address", this.address);
        if (this.employerNif != 0) builder.set("employerNif", this.employerNif);

        return builder.build();
    }

    public Entity getUpdatedUser(Entity originalUser) {
        Entity.Builder builder = Entity.newBuilder(originalUser);

        if (this.email != null) builder.set("email", this.email);
        if (this.userName != null) builder.set("userName", this.userName);
        if (this.fullName != null) builder.set("fullName", this.fullName);
        if (this.phoneNum != null) builder.set("phoneNum", this.phoneNum);
        if (this.password != null) builder.set("password", this.password);
        builder.set("isPublic", this.isPublic);
        if (this.role != null) builder.set("role", this.role);
        if (this.accountState != null) builder.set("accountState", this.accountState);
        if (this.ccNum != null) builder.set("ccNum", this.ccNum);
        if (this.nif != 0) builder.set("nif", this.nif);
        if (this.employer != null) builder.set("employer", this.employer);
        if (this.function != null) builder.set("function", this.function);
        if (this.address != null) builder.set("address", this.address);
        if (this.employerNif != 0) builder.set("employerNif", this.employerNif);

        return builder.build();
    }
}
