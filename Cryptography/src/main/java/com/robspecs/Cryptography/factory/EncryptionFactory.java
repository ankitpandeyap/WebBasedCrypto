package com.robspecs.Cryptography.factory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.Enums.Algorithm;
import com.robspecs.Cryptography.service.EncryptionService;

@Component
public class EncryptionFactory {

    private final Map<Algorithm, EncryptionService> serviceMap;
    private static final Logger logger = LoggerFactory.getLogger(EncryptionFactory.class);

    @Autowired
    public EncryptionFactory(List<EncryptionService> services) {
        logger.debug("EncryptionFactory initializing with {} services", services.size());
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
                    logger.debug("Registered {} encryption service", algorithm);
                } catch (IllegalArgumentException e) {
                    // Handle cases where the @Service value doesn't match an enum name
                    logger.warn("Service annotation value '{}' does not match any known Algorithm enum. Service not registered.", annotation.value());
                    // You might want to throw an exception here depending on your error handling strategy
                }
            } else {
                logger.warn("Service {} has no @Service annotation, and will not be registered in EncryptionFactory.", service.getClass().getName());
            }
        }
        logger.debug("EncryptionFactory initialized with {} services", serviceMap.size());
    }

    public EncryptionService getEncryptionService(Algorithm algorithm) {
        EncryptionService service = serviceMap.get(algorithm);
        if (service == null) {
            logger.error("Unsupported encryption type: {}", algorithm.name());
            throw new IllegalArgumentException("Unsupported encryption type: " + algorithm.name());
        }

        if (algorithm == Algorithm.MONO_ALPHABETIC_CIPHER || algorithm == Algorithm.CUSTOM) {
            logger.warn("SECURITY WARNING: Requesting cryptographically weak algorithm '{}'. " +
                        "These algorithms (Monoalphabetic, Custom/Caesar) are for demonstration/educational purposes ONLY " +
                        "and should NOT be used for sensitive data in a production environment.", algorithm.name());
        }
        logger.debug("Returning {} encryption service for algorithm {}", service.getClass().getSimpleName(), algorithm.name());
        return service;
    }
}
