package id.co.swipepay.apigateway.repository;

import id.co.swipepay.apigateway.entity.redis.UserToken;

import java.util.Map;

public interface UserTokenRepository {

    void save(UserToken user);

    Map<Long, UserToken> findAll();

    UserToken findById(Long id);

    void update(UserToken user);
    void delete(String id);
}
