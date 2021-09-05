package id.co.swipepay.apigateway.entity.redis;

import lombok.Builder;
import lombok.Data;

import java.io.Serializable;

@Data
@Builder
public class UserToken implements Serializable {
    private Long id;
    private String username;
    private String token;
    private Long millis;
}
