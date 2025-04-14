package pt.unl.fct.di.apdc.firstwebapp.util;

import com.google.cloud.datastore.*;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class WorkSheet {
    public String workSheetID;
    public String description;
    public String propertyType;
    public boolean isAdjudicated;
    public String adjudicationDate;
    public String startDate;
    public String endDate;
    public String partnerUserName;
    public String adjudicationEntity;
    public int companyNif;
    public String workState;
    public String observations;

    private static final DateFormat fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static final Set<String> ALLOWED_WORK_STATES = new HashSet<>(Arrays.asList("NOT_STARTED", "IN_PROGRESS", "COMPLETED"));

    public WorkSheet() {

    }

    public WorkSheet(String workSheetID, String description, String propertyType, boolean isAdjudicated,
                     String adjudicationDate, String startDate, String endDate, String partnerUserName,
                     String adjudicationEntity, int companyNif, String workState, String observations) {
        this.workSheetID = workSheetID;
        this.description = description;
        this.propertyType = propertyType;
        this.isAdjudicated = isAdjudicated;
        this.adjudicationDate = adjudicationDate;
        this.startDate = startDate;
        this.endDate = endDate;
        this.partnerUserName = partnerUserName;
        this.adjudicationEntity = adjudicationEntity;
        this.companyNif = companyNif;
        this.workState = workState;
        this.observations = observations;
    }

    private boolean fieldNonEmpty(String field) {
        return field != null && !field.isBlank();
    }

    public boolean hasMandatoryFields() {
        return fieldNonEmpty(workSheetID) &&
                fieldNonEmpty(description) &&
                fieldNonEmpty(propertyType);
    }

    public boolean isBefore(String dateString1, String dateString2) {
        try {
            fmt.setLenient(false);
            Date date1 = fmt.parse(dateString1);
            Date date2 = fmt.parse(dateString2);
            return date1.before(date2);
        }
        catch (ParseException e) {
            return false;
        }
    }

    private boolean isValidNif(int nif) {
        int numDigits = (int) (Math.log10(nif) + 1);
        return nif >= 0 && (nif == 0 || numDigits == 9);
    }

    public boolean isValidState() {
        return ALLOWED_WORK_STATES.contains(this.workState.toUpperCase());
    }

    public boolean adjudicatedFieldsValid() {
        if (!(isBefore(this.adjudicationDate, this.startDate) && isBefore(this.startDate, this.endDate))) {
            return false;
        }
        return fieldNonEmpty(this.partnerUserName) &&
                fieldNonEmpty(this.adjudicationEntity) &&
                isValidNif(this.companyNif) &&
                (fieldNonEmpty(this.workState) && isValidState()) &&
                fieldNonEmpty(this.observations);

    }

    public boolean isValid() {
        if (!hasMandatoryFields()) {
            return false;
        }
        if (this.isAdjudicated) {
            return adjudicatedFieldsValid();
        }
        return true;
    }
}
