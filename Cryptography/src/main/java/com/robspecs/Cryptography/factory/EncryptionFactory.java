package com.robspecs.Cryptography.factory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.EncryptionService;
import com.robspecs.Cryptography.Enums.Algorithm;	

@Component
public class EncryptionFactory {

    private final Map<Algorithm, EncryptionService> serviceMap;

    @Autowired
    public EncryptionFactory(List<EncryptionService> services) {
        serviceMap = new HashMap<>();
        for (EncryptionService service : services) {
            Service annotation = service.getClass().getAnnotation(Service.class);
            if (annotation != null) {
                // Assuming your @Service annotation value matches the enum names
                // For example, if @Service("RSA") is on RSAEncryptionService,
                // and you have Algorithm.RSA, this will work.
                try {
                    Algorithm algorithm = Algorithm.valueOf(annotation.value().toUpperCase());
                    serviceMap.put(algorithm, service);
                } catch (IllegalArgumentException e) {
                    // Handle cases where the @Service value doesn't match an enum name
                    //System.err.println("Warning: Service annotation value '" + annotation.value() +
                      //                 "' does not match any known Algorithm enum. Service not registered.");
                    // You might want to throw an exception here depending on your error handling strategy
                }
            }
        }
    }

    public EncryptionService getEncryptionService(Algorithm algorithm) {
        EncryptionService service = serviceMap.get(algorithm);
        if (service == null) {
            throw new IllegalArgumentException("Unsupported encryption type: " + algorithm.name());
        }
        return service;
    }
}