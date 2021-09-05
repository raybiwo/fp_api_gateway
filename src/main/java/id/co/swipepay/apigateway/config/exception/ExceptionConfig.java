package id.co.swipepay.apigateway.config.exception;

import id.co.swipepay.exception.ApiExceptionHandler;
import id.co.swipepay.model.Response;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import static id.co.swipepay.constant.Code.INTERNAL_SERVER_ERROR;
import static id.co.swipepay.constant.Code.code;

@RestControllerAdvice
@ControllerAdvice
public class ExceptionConfig extends ResponseEntityExceptionHandler {

    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<Object> internalServerException(
            NullPointerException ex) {
        Response<Object> response = Response.internalServerError();
        response.addErrorMsgToResponse(ex, code(INTERNAL_SERVER_ERROR));
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
