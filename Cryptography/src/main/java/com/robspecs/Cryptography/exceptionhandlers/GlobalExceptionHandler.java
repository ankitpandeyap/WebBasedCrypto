
package com.robspecs.Cryptography.exceptionhandlers;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException; // For Spring Security auth failures
import org.springframework.web.bind.MethodArgumentNotValidException; // For @Valid annotation errors
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

// Import all your custom exceptions
import com.robspecs.Cryptography.exceptions.EmailSendingException;
import com.robspecs.Cryptography.exceptions.EncryptionDecryptionException;
import com.robspecs.Cryptography.exceptions.InboxRetrievalException;
import com.robspecs.Cryptography.exceptions.InvalidOtpException;
import com.robspecs.Cryptography.exceptions.InvalidPasskeyException;
import com.robspecs.Cryptography.exceptions.JWTBlackListedTokenException;
import com.robspecs.Cryptography.exceptions.MissingEncryptionKeyException;
import com.robspecs.Cryptography.exceptions.NotFoundException;
import com.robspecs.Cryptography.exceptions.OtpCooldownException;
import com.robspecs.Cryptography.exceptions.TokenNotFoundException;
import com.robspecs.Cryptography.exceptions.TooManyOtpAttemptsException;
import com.robspecs.Cryptography.exceptions.UnauthorizedException;
import com.robspecs.Cryptography.exceptions.UserAlreadyExistsException;

import io.jsonwebtoken.JwtException; // For general JWT issues

/**
 * Global Exception Handler for the Cryptography application. This class
 * intercepts exceptions thrown by controllers and services and provides a
 * centralized, consistent way to return error responses to the client.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

	private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

	/**
	 * Handles NotFoundException (HTTP 404). Occurs when a requested resource (e.g.,
	 * user, message) is not found.
	 */
	@ExceptionHandler(NotFoundException.class)
	public ResponseEntity<String> handleNotFoundException(NotFoundException ex) {
		logger.warn("NotFoundException caught: {}", ex.getMessage());
		return new ResponseEntity<>(ex.getMessage(), HttpStatus.NOT_FOUND);
	}

	/**
	 * Handles UnauthorizedException (HTTP 403 Forbidden). Occurs when an
	 * authenticated user attempts to access a resource they don't have permission
	 * for.
	 */
	@ExceptionHandler(UnauthorizedException.class)
	public ResponseEntity<String> handleUnauthorizedException(UnauthorizedException ex) {
		logger.warn("UnauthorizedException caught: {}", ex.getMessage());
		return new ResponseEntity<>(ex.getMessage(), HttpStatus.FORBIDDEN);
	}

	/**
	 * Handles InvalidPasskeyException (HTTP 403 Forbidden). Occurs when an
	 * incorrect passkey is provided for decryption/verification.
	 */
	@ExceptionHandler(InvalidPasskeyException.class)
	public ResponseEntity<String> handleInvalidPasskeyException(InvalidPasskeyException ex) {
		logger.warn("InvalidPasskeyException caught: {}", ex.getMessage());
		return new ResponseEntity<>(ex.getMessage(), HttpStatus.FORBIDDEN);
	}

	/**
	 * Handles MissingEncryptionKeyException (HTTP 500 Internal Server Error).
	 * Occurs when a user's account is missing critical encryption key components.
	 */
	@ExceptionHandler(MissingEncryptionKeyException.class)
	public ResponseEntity<String> handleMissingEncryptionKeyException(MissingEncryptionKeyException ex) {
		logger.error("MissingEncryptionKeyException caught: {}", ex.getMessage(), ex);
		return new ResponseEntity<>(ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
	}

	/**
	 * Handles EncryptionDecryptionException (HTTP 500 Internal Server Error).
	 * Occurs during general cryptographic failures (e.g., malformed data, algorithm
	 * issues).
	 */
	@ExceptionHandler(EncryptionDecryptionException.class)
	public ResponseEntity<String> handleEncryptionDecryptionException(EncryptionDecryptionException ex) {
		logger.error("EncryptionDecryptionException caught: {}", ex.getMessage(), ex);
		return new ResponseEntity<>(ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
	}

	/**
	 * Handles UserAlreadyExistsException (HTTP 409 Conflict). Occurs when a user
	 * tries to register with an email that already exists.
	 */
	@ExceptionHandler(UserAlreadyExistsException.class)
	public ResponseEntity<String> handleUserAlreadyExistsException(UserAlreadyExistsException ex) {
		logger.warn("UserAlreadyExistsException caught: {}", ex.getMessage());
		return new ResponseEntity<>(ex.getMessage(), HttpStatus.CONFLICT);
	}

	/**
	 * Handles OtpCooldownException (HTTP 429 Too Many Requests). Occurs when an OTP
	 * request is made too soon.
	 */
	@ExceptionHandler(OtpCooldownException.class)
	public ResponseEntity<String> handleOtpCooldownException(OtpCooldownException ex) {
		logger.warn("OtpCooldownException caught: {}", ex.getMessage());
		return new ResponseEntity<>(ex.getMessage(), HttpStatus.TOO_MANY_REQUESTS);
	}

	/**
	 * Handles InvalidOtpException (HTTP 400 Bad Request). Occurs when an OTP is
	 * invalid or expired.
	 */
	@ExceptionHandler(InvalidOtpException.class)
	public ResponseEntity<String> handleInvalidOtpException(InvalidOtpException ex) {
		logger.warn("InvalidOtpException caught: {}", ex.getMessage());
		return new ResponseEntity<>(ex.getMessage(), HttpStatus.BAD_REQUEST);
	}

	/**
	 * Handles TooManyOtpAttemptsException (HTTP 429 Too Many Requests). Occurs when
	 * a user exceeds max OTP verification attempts.
	 */
	@ExceptionHandler(TooManyOtpAttemptsException.class)
	public ResponseEntity<String> handleTooManyOtpAttemptsException(TooManyOtpAttemptsException ex) {
		logger.warn("TooManyOtpAttemptsException caught: {}", ex.getMessage());
		return new ResponseEntity<>(ex.getMessage(), HttpStatus.TOO_MANY_REQUESTS);
	}

	/**
	 * Handles EmailSendingException (HTTP 500 Internal Server Error). Occurs when
	 * there's a problem sending an email.
	 */
	@ExceptionHandler(EmailSendingException.class)
	public ResponseEntity<String> handleEmailSendingException(EmailSendingException ex) {
		logger.error("EmailSendingException caught: {}", ex.getMessage(), ex);
		return new ResponseEntity<>(ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
	}

	/**
	 * Handles TokenNotFoundException (HTTP 401 Unauthorized). Occurs when a
	 * required JWT token (e.g., refresh token in cookie, access token in header) is
	 * missing.
	 */
	@ExceptionHandler(TokenNotFoundException.class)
	public ResponseEntity<String> handleTokenNotFoundException(TokenNotFoundException ex) {
		logger.warn("TokenNotFoundException caught: {}", ex.getMessage());
		return new ResponseEntity<>(ex.getMessage(), HttpStatus.UNAUTHORIZED);
	}

	/**
	 * Handles JWTBlackListedTokenException (HTTP 401 Unauthorized). Occurs when a
	 * JWT token is valid but has been explicitly blacklisted.
	 */
	@ExceptionHandler(JWTBlackListedTokenException.class)
	public ResponseEntity<String> handleJWTBlackListedTokenException(JWTBlackListedTokenException ex) {
		logger.warn("JWTBlackListedTokenException caught: {}", ex.getMessage());
		return new ResponseEntity<>(ex.getMessage(), HttpStatus.UNAUTHORIZED);
	}

	/**
	 * Handles general JwtException (HTTP 401 Unauthorized). Catches various JWT
	 * parsing/validation errors (e.g., MalformedJwtException, SignatureException).
	 */
	@ExceptionHandler(JwtException.class)
	public ResponseEntity<String> handleJwtException(JwtException ex) {
		logger.warn("JwtException caught: {}", ex.getMessage());
		return new ResponseEntity<>("Authentication failed: Invalid token.", HttpStatus.UNAUTHORIZED);
	}

	/**
	 * Handles BadCredentialsException (HTTP 401 Unauthorized). Typically thrown by
	 * Spring Security for incorrect username/password during login.
	 */
	@ExceptionHandler(BadCredentialsException.class)
	public ResponseEntity<String> handleBadCredentialsException(BadCredentialsException ex) {
		logger.warn("BadCredentialsException caught: {}", ex.getMessage());
		return new ResponseEntity<>("Invalid username or password.", HttpStatus.UNAUTHORIZED);
	}

	/**
	 * Handles MethodArgumentNotValidException (HTTP 400 Bad Request). Occurs
	 * when @Valid annotation fails validation on a @RequestBody.
	 */
	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Map<String, String>> handleValidationExceptions(MethodArgumentNotValidException ex) {
		Map<String, String> errors = new HashMap<>();
		ex.getBindingResult().getFieldErrors()
				.forEach(error -> errors.put(error.getField(), error.getDefaultMessage()));
		logger.warn("Validation errors: {}", errors);
		return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST);
	}

	/**
	 * Generic exception handler for any unhandled exceptions (HTTP 500 Internal
	 * Server Error). This is the fallback for any exception not specifically caught
	 * by other handlers.
	 */
	@ExceptionHandler(Exception.class)
	public ResponseEntity<String> handleAllUncaughtExceptions(Exception ex) {
		logger.error("An unexpected error occurred: {}", ex.getMessage(), ex);
		return new ResponseEntity<>("An unexpected internal server error occurred.", HttpStatus.INTERNAL_SERVER_ERROR);
	}
	
	  @ExceptionHandler(InboxRetrievalException.class)
	    public ResponseEntity<String> handleInboxRetrievalException(InboxRetrievalException ex) {
	        logger.error("InboxRetrievalException caught: {}", ex.getMessage(), ex);
	        return new ResponseEntity<>(ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
	    }
}
