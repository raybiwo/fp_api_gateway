package id.co.swipepay.apigateway.filter;

import com.alibaba.fastjson.JSON;
import id.co.swipepay.apigateway.config.jwt.JwtAuthenticationConfig;
import id.co.swipepay.apigateway.entity.redis.UserToken;
import id.co.swipepay.apigateway.repository.UserTokenRepository;
import id.co.swipepay.apigateway.web.HeaderMapRequestWrapper;
import id.co.swipepay.model.Response;
import id.co.swipepay.model.ResponseError;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.*;

import static id.co.swipepay.apigateway.util.StringUtils.classToString;
import static id.co.swipepay.constant.Code.*;
import static id.co.swipepay.constant.MessageType.ILLEGAL_TOKEN;
import static id.co.swipepay.utils.JwtTokenUtil.getAllClaimsFromToken;
import static id.co.swipepay.utils.Translator.localMessage;
import static id.co.swipepay.utils.Translator.localMessageWithId;

/**
 * Authenticate requests with header 'Authorization: Bearer jwt-token'.
 *
 * @author raybiwo 2020/9/1
 */
@Slf4j
public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {

    private JwtAuthenticationConfig config;
    private UserTokenRepository userTokenRepository;
    private String correlationId;
    private String username;
    private String role;
    private String userId;

    public JwtTokenAuthenticationFilter(JwtAuthenticationConfig config, UserTokenRepository userTokenRepository) {
        this.config = config;
        this.userTokenRepository = userTokenRepository;
    }

    private static final List<MediaType> VISIBLE_TYPES = Arrays.asList(
            MediaType.valueOf("text/*"),
            MediaType.APPLICATION_FORM_URLENCODED,
            MediaType.APPLICATION_JSON,
            MediaType.APPLICATION_XML,
            MediaType.valueOf("application/*+json"),
            MediaType.valueOf("application/*+xml"),
            MediaType.MULTIPART_FORM_DATA
    );

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse rsp, FilterChain filterChain)
            throws ServletException, IOException {
        boolean isFilterError = false;
        ResponseError error = new ResponseError();
        String token = req.getHeader(config.getHeader());
        correlationId = getCorrelationId();

        try {
            MDC.put("CorrelationId", correlationId);
            if (isTokenExist(token)) {
                token = token.replace(config.getPrefix() + " ", "");
                try {
                    Claims claims = getAllClaimsFromToken(token, config.getSecret());
                    username = claims.getSubject();
                    role = (String) claims.get("role");
                    userId = (String) claims.get("id");

                    if (!isTokenMatch(token, userId)) {
                        error.setMessage(localMessage(ILLEGAL_TOKEN)).setCode(code(UNAUTHORIZED));
                        isFilterError = true;
                    } else {
                        if (username != null) {
                            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username,
                                    null, getAuthorities(role));
                            SecurityContextHolder.getContext().setAuthentication(auth);
                        }
                        isFilterError = false;
                    }

                } catch (IllegalArgumentException e) {
                    isFilterError = true;
                    logger.error("Unable to get JWT Token ");
                    error.setMessage(localMessage(ILLEGAL_TOKEN)).setCode(code(UNAUTHORIZED));
                } catch (ExpiredJwtException e) {
                    isFilterError = true;
                    logger.error("JWT Token has expired");
                    error.setMessage(localMessageWithId(ILLEGAL_TOKEN, 1)).setCode(code(EXPIRED_TOKEN));
                } catch (SignatureException e) {
                    isFilterError = true;
                    logger.error("Authentication Signature Failed. Illegal Token");
                    error.setMessage(localMessage(ILLEGAL_TOKEN)).setCode(code(UNAUTHORIZED));
                } catch (MalformedJwtException e) {
                    isFilterError = true;
                    logger.error("Authentication Failed. Illegal Token");
                    error.setMessage(localMessage(ILLEGAL_TOKEN)).setCode(code(UNAUTHORIZED));
                }
            }

            if (isAsyncDispatch(req)) {
                filterChain.doFilter(req, rsp);
            } else {
                doFilterWrapped(wrapRequest(req),
                        wrapResponse(rsp),
                        filterChain,
                        isFilterError,
                        error);
            }
        } finally {
            MDC.remove("CorrelationId");
        }
    }

    private boolean isTokenMatch(String token, String userId) {
        UserToken userToken = userTokenRepository.findById(Long.valueOf(userId));
        return userToken.getToken().equals(token);
    }

    private boolean isTokenExist(String token) {
        return token != null && token.startsWith(config.getPrefix() + " ");
    }

    protected void doFilterWrapped(ContentCachingRequestWrapper request, ContentCachingResponseWrapper response, FilterChain filterChain, boolean isFilterError, ResponseError error) throws ServletException, IOException {
        try {
            writeLogBeforeRequest(request);
            if (isFilterError) {
                sendResponseError(response, error);
            } else {
                HeaderMapRequestWrapper requestWrapper = new HeaderMapRequestWrapper(request);
                requestWrapper.addHeader("correlation", correlationId);
                requestWrapper.addHeader("username", username);
                requestWrapper.addHeader("role", role);
                requestWrapper.addHeader("userId", userId);

                filterChain.doFilter(requestWrapper, response);
            }
        } finally {
            writeLogAfterRequest(request, response);
            response.copyBodyToResponse();
        }
    }

    protected void writeLogBeforeRequest(ContentCachingRequestWrapper request) {
        if (logger.isInfoEnabled()) {
            logRequestHeader(request, "request : ");
        }
    }

    protected void writeLogAfterRequest(ContentCachingRequestWrapper request, ContentCachingResponseWrapper response) {
        if (logger.isInfoEnabled()) {
            logRequestBody(request, "request : ");
            logResponse(response, "response : ");
        }
    }

    private void logResponse(ContentCachingResponseWrapper response, String prefix) {
        int status = response.getStatus();
        log.info("{} {} {}", prefix, status, HttpStatus.valueOf(status).getReasonPhrase());
        response.getHeaderNames().forEach(headerName ->
                response.getHeaders(headerName).forEach(headerValue ->
                        log.info("{} {}: {}", prefix, headerName, headerValue)));
        byte[] content = response.getContentAsByteArray();
        if (content.length > 0) {
            log.info(" --- Response Body ---");
            logContent(content, response.getContentType(), response.getCharacterEncoding(), prefix, "ResponseBody");
        }
    }

    private String getCorrelationId() {
        return UUID.randomUUID().toString().toUpperCase().replace("-", "") + " |";
    }

    private Set<SimpleGrantedAuthority> getAuthorities(String role) {
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        if (role.equals("0")) {
            authorities.add(new SimpleGrantedAuthority("ADMIN"));
        } else {
            authorities.add(new SimpleGrantedAuthority("USER"));
        }
        return authorities;
    }

    private void logRequestHeader(ContentCachingRequestWrapper request, String prefix) {
        String queryString = request.getQueryString();
        if (queryString == null) {
            log.info("{} {} {}", prefix, request.getMethod(), request.getRequestURI());
        } else {
            log.info("{} {} {}?{}", prefix, request.getMethod(), request.getRequestURI(), queryString);
        }
        Collections.list(request.getHeaderNames()).forEach(headerName ->
                Collections.list(request.getHeaders(headerName)).forEach(headerValue ->
                        log.info("{} {}: {}", prefix, headerName, headerValue)));
        log.info(" Session ID: ", RequestContextHolder.currentRequestAttributes().getSessionId());
    }

    private void logRequestBody(ContentCachingRequestWrapper request, String prefix) {
        byte[] content = request.getContentAsByteArray();
        if (content.length > 0) {
            log.info(" --- Request Body ---");
            logContent(content, request.getContentType(), request.getCharacterEncoding(), prefix, "RequestBody");
        }
    }

    private void logContent(byte[] content, String contentType, String contentEncoding, String prefix, String state) {
        boolean visible = true;

        if (contentType != null) {
            MediaType mediaType = MediaType.valueOf(contentType);
            visible = VISIBLE_TYPES.stream().anyMatch(visibleType -> visibleType.includes(mediaType));
        }

        if (visible) {
            try {
                String contentString = new String(content, contentEncoding);
                if (contentType!=null) {
                    if (contentType.contains("application/json")) {
                        log.info(state+ " : " + JSON.parse(contentString.replace("/\r?\n|\r/g", "")));
                    }
                }
            } catch (UnsupportedEncodingException e) {
                log.info("{} [{} bytes content]", prefix, content.length);
            }
        } else {
            log.info("{} [{} bytes content]", prefix, content.length);
        }
    }

    private static ContentCachingRequestWrapper wrapRequest(HttpServletRequest request) {
        if (request instanceof ContentCachingRequestWrapper) {
            return (ContentCachingRequestWrapper) request;
        } else {
            return new ContentCachingRequestWrapper(request);
        }
    }

    private static ContentCachingResponseWrapper wrapResponse(HttpServletResponse response) {
        if (response instanceof ContentCachingResponseWrapper) {
            return (ContentCachingResponseWrapper) response;
        } else {
            return new ContentCachingResponseWrapper(response);
        }
    }

    private void sendResponseError(HttpServletResponse rsp, ResponseError error) throws IOException {
        Response<Object> response = Response.unauthorized();
        error.setTimestamp(System.currentTimeMillis());
        response.setError(error);
        logger.error(JSON.parse(classToString(response).replace("/\r?\n|\r/g", "")));
        rsp.getWriter().write(classToString(response));
    }
}
