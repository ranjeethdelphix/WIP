package com.delphix.masking.customer.mtb;

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

public class fullname implements MaskingAlgorithm<String> {

    /**
     * Masks String object
     * @param input The String object to be masked. This method should handle null inputs.
     * @return Returns the masked value.
     */
    @JsonProperty("Individual_name_algorithm")
    @JsonPropertyDescription("AlgorithmInstanceReference of type string")
    public AlgorithmInstanceReference Individual_name_algorithm;
    private MaskingAlgorithm<String> Ind_algo_instance;

    @JsonProperty("Company_name_algorithm")
    @JsonPropertyDescription("AlgorithmInstanceReference of type string")
    public AlgorithmInstanceReference Company_name_algorithm;
    private MaskingAlgorithm<String> Cmp_algo_instance;

    public boolean getAllowFurtherInstances() {
        return true;
    }

    public Collection<MaskingComponent> getDefaultInstances() {
        return null;
    }

    public void setup(ComponentService serviceProvider) {
        try {
            this.Ind_algo_instance = serviceProvider.getAlgorithmByName(this.Individual_name_algorithm, MaskingType.STRING);
            this.Cmp_algo_instance = serviceProvider.getAlgorithmByName(this.Company_name_algorithm, MaskingType.STRING);
        } catch (Exception var3) {
            throw new RuntimeException(var3);
        }
    }

    private static boolean empty(String s) {
        return s == null || s.trim().isEmpty();
    }

    @Override
    public String mask(@Nullable String input) throws MaskingException {
        String output;
        if (empty(input)) {
            return input;
        } else {
            if (input.trim().startsWith("*")) {
                output =  '*' + this.Cmp_algo_instance.mask(input);
            }
            else {
                output =  this.Ind_algo_instance.mask(input);
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
        return "fullname";
    }
}
