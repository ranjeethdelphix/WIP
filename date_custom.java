package com.delphix.masking.customer.mtb;

import java.time.LocalDateTime;
import java.time.format.*;
import com.delphix.masking.api.plugin.MaskingAlgorithm;
import com.delphix.masking.api.plugin.MaskingComponent;
import com.delphix.masking.api.plugin.MaskingAlgorithm.MaskingType;
import com.delphix.masking.api.plugin.exception.MaskingException;
import com.delphix.masking.api.plugin.referenceType.AlgorithmInstanceReference;
import com.delphix.masking.api.provider.ComponentService;
import java.lang.String;
import java.util.Collection;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import javax.annotation.Nullable;

public class date_custom implements MaskingAlgorithm<String> {

    /**
     * Masks String object
     * @param input The String object to be masked. This method should handle null inputs.
     * @return Returns the masked value.
     */
    @JsonProperty("date_format")
    @JsonPropertyDescription("date format")
    public String date_format;
    
    @JsonProperty("change_days")
    @JsonPropertyDescription("No of days to change along with direction")
    public String change_days;
    private int minDays;
    private DateTimeFormatter internal_dateformat, day_of_the_year;
	private boolean century;
	
    public boolean getAllowFurtherInstances() {
        return true;
    }

    public Collection<MaskingComponent> getDefaultInstances() {
        return null;
    }

    public void setup(ComponentService serviceProvider) {
		
		if (this.change_days == null || this.change_days.trim().isEmpty()) {
			this.minDays = 31;
		} else {
			this.minDays = Integer.parseInt(change_days);
		}
		
		this.day_of_the_year = DateTimeFormatter.ofPattern("D");
		
		if (this.date_format.toUpperCase() == "CYYJJJ") {
			this.internal_dateformat = DateTimeFormatter.ofPattern("yyD");
			this.century = true;
		} else if (this.date_format.toUpperCase() == "CYYMMDD") {
			this.internal_dateformat = DateTimeFormatter.ofPattern("yyMMdd");
			this.century = true;
		} else if (this.date_format.toUpperCase() == "YYMMDD") {
			this.internal_dateformat = DateTimeFormatter.ofPattern("yyMMdd");
			this.century = false;
		} else if (this.date_format.toUpperCase() == "MMDDYY") {
			this.internal_dateformat = DateTimeFormatter.ofPattern("MMddyy");
			this.century = false;
		} else if (this.date_format.toUpperCase() == "YY-MM-DD") {
			this.internal_dateformat = DateTimeFormatter.ofPattern("yy-MM-dd");
			this.century = false;
		} else if (this.date_format.toUpperCase() == "YYYY-MM-DD") {
			this.internal_dateformat = DateTimeFormatter.ofPattern("yyyy-MM-dd");
			this.century = false;
		} else if (this.date_format.toUpperCase() == "MM-DD-YY") {
			this.internal_dateformat = DateTimeFormatter.ofPattern("MM-dd-yy");
			this.century = false;
		}
    }

    private static boolean empty(String s) {
        return s == null || s.trim().isEmpty();
    }

    @Override
    public String mask(@Nullable String input) throws MaskingException {
        String output;
        LocalDateTime ldt = null, ldt2 = null;
		
		if (empty(input)) {
            return input;
        } else {
            if (this.century) {
				ldt = LocalDateTime.parse(input.substring(1), this.internal_dateformat);
			}
			else {
				ldt = LocalDateTime.parse(input, this.internal_dateformat);
			}
			
			int monthValue = ldt.getMonthValue();
			
			if (monthValue == 1) {
				ldt2 = ldt.plusDays(minDays);
			} else {
				ldt2 = ldt.minusDays(minDays);
			}
			
			if (this.century) {
				output = input.charAt(0) + ldt2.format(this.internal_dateformat);
			} else {
				output = input.charAt(0) + ldt2.format(this.internal_dateformat);
			}
			
			return output;
		}
    }



    /**
     * Get the recommended name of this Algorithm.
     * @return The name of this algorithm
     */
    @Override
    public String getName() {
        // TODO: Change this if you'd like to name your algorithm differently from the Java class.
        return "date_custom";
    }
}
