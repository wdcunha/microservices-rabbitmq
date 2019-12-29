package com.example.gatewayzuul.controller;

import com.example.gatewayzuul.exception.CognitoException;
import com.example.gatewayzuul.security.model.ErrorMessage;
import com.example.gatewayzuul.security.model.ResponseWrapper;
import com.example.gatewayzuul.security.model.RestErrorList;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.servlet.http.HttpServletRequest;

import static java.util.Collections.singletonMap;

@ControllerAdvice
@EnableWebMvc
public class ExceptionController extends ResponseEntityExceptionHandler {

    /**
     * handleException - Handles all the Exception recieving a request, responseWrapper.
     */
    @ExceptionHandler(Exception.class)
    public @ResponseBody ResponseEntity<ResponseWrapper> handleException(HttpServletRequest request, ResponseWrapper responseWrapper){

        return ResponseEntity.ok(responseWrapper);
    }

    /**
     * handleIOException - Handles all the Authentication Exceptions of the application.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ResponseWrapper> handleIOException(HttpServletRequest request, CognitoException e){

        RestErrorList errorList = new RestErrorList(HttpStatus.NOT_ACCEPTABLE, new ErrorMessage(e.getErrorMessage(),e.getErrorCode(), e.getDetailErrorMessage()));
        ResponseWrapper responseWrapper = new ResponseWrapper(null, singletonMap("status", HttpStatus.NOT_ACCEPTABLE), errorList);


        return ResponseEntity.ok(responseWrapper);
    }

    /**
     * handleJwtException - Handles all the JWT Exceptions of the application.
     */
    public ResponseWrapper handleJwtException(HttpServletRequest request, CognitoException e){

        RestErrorList errorList = new RestErrorList(HttpStatus.UNAUTHORIZED, new ErrorMessage(e.getErrorMessage(),e.getErrorCode(), e.getDetailErrorMessage()));
        ResponseWrapper responseWrapper = new ResponseWrapper(null, singletonMap("status", HttpStatus.UNAUTHORIZED), errorList);


        return responseWrapper;
    }
}
