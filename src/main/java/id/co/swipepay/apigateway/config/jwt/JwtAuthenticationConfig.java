package id.co.swipepay.apigateway.config.jwt;

import lombok.Getter;
import lombok.ToString;
import org.springframework.beans.factory.annotation.Value;

/**
 * Config JWT.
 *
 * @author raybiwo 2017/10/18
 */
@Getter
@ToString
public class JwtAuthenticationConfig {

    @Value("/login")
    private String url;

    @Value("Authorization")
    private String header;

    @Value("Bearer")
    private String prefix;

    @Value("#{2160 * 60 * 60}")
    private int expiration; // default 3 Month

    @Value("swipepos")
    private String secret;
}
