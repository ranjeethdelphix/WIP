package com.delphix.masking.customer.mtb;

import com.delphix.masking.api.plugin.MaskingAlgorithm;
import java.lang.String;
import javax.annotation.Nullable;
import java.util.List;
import java.util.Random;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;


public class gender_mtb implements MaskingAlgorithm<String> {

    /**
     * Masks String object
     * @param input The String object to be masked. This method should handle null inputs.
     * @return Returns the masked value.
     */
    @JsonProperty("listValues")
    @JsonPropertyDescription("List of values to randomize from")
    public List<String> listValues;

    @Override
    public String mask(@Nullable String input) {
        // TODO: change the default implementation.
        Random random = new Random();
        int randomIndex = random.nextInt(this.listValues.size());
        return this.listValues.get(randomIndex);

    }

    /**
     * Get the recommended name of this Algorithm.
     * @return The name of this algorithm
     */
    @Override
    public String getName() {
        // TODO: Change this if you'd like to name your algorithm differently from the Java class.
        return "gender_mtb";
    }
}
