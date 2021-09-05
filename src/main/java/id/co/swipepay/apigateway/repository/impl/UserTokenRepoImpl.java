package id.co.swipepay.apigateway.repository.impl;

import id.co.swipepay.apigateway.entity.redis.UserToken;
import id.co.swipepay.apigateway.repository.UserTokenRepository;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;

import static id.co.swipepay.apigateway.util.StringUtils.classToString;
import static id.co.swipepay.apigateway.util.StringUtils.stringToClass;

@Repository
public class UserTokenRepoImpl implements UserTokenRepository {

    private final RedisTemplate<String, UserToken> redisTemplate;
    private final HashOperations hashOperations; //to access redis cache

    public UserTokenRepoImpl(RedisTemplate<String, UserToken> redisTemplate) {
        this.redisTemplate = redisTemplate;
        this.hashOperations = redisTemplate.opsForHash();
    }

    @Override
    public void save(UserToken user) {
        String userToken = classToString(user);
        hashOperations.put("USER_TOKEN",
                user.getId(),
                userToken);
    }

    @Override
    public Map<Long, UserToken> findAll() {
        Map<Long, String> userMap = hashOperations.entries("USER_TOKEN");
        Map<Long, UserToken> userTokenMap = new HashMap<>();
        for (Map.Entry<Long, String> entry: userMap.entrySet()) {
            Long key = entry.getKey();
            String value = entry.getValue();
            UserToken userToken = stringToClass(value, UserToken.class);
            userTokenMap.put(key, userToken);
        }
        return userTokenMap;
    }

    @Override
    public UserToken findById(Long id) {
        UserToken userToken = stringToClass((String) hashOperations.get("USER_TOKEN",id), UserToken.class);
        return userToken;
    }

    @Override
    public void update(UserToken user) {
        save(user);
    }

    @Override
    public void delete(String id) {
        hashOperations.delete("USER_TOKEN",id);
    }
}
