/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eu.seal.as.model.factories;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import eu.seal.as.model.pojo.MSConfigurationResponse.MicroService;

import java.io.IOException;

/**
 *
 * @author nikos
 */
public class MSConfigurationResponseFactory {

    public static MicroService[] makeMSConfigResponseFromJSON(String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
//        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper.readValue(json, MicroService[].class);
    }

}
