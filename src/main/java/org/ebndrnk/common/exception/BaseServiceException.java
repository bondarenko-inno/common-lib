package org.ebndrnk.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * OrderServiceException
 * <p>
 * Base class for all custom exceptions in the User Service module.
 * <p>
 * This runtime exception is intended to be extended by specific
 * custom exceptions to represent various error scenarios in the service.
 * It allows you to encapsulate domain-specific error information
 * and propagate meaningful error messages to higher layers
 * or to the API response.
 * <p>
 * Example usage:
 * <pre>
 * throw new UserNotFoundException("User with id 10 not found");
 * </pre>
 */
@Getter
public abstract class BaseServiceException extends RuntimeException {

    private final HttpStatus status;
    private final String errorCode;

    protected BaseServiceException(String message, HttpStatus status, String errorCode) {
        super(message);
        this.status = status;
        this.errorCode = errorCode;
    }

}
