package id.co.swipepay.apigateway.config.security;

import id.co.swipepay.apigateway.config.jwt.JwtAuthenticationConfig;
import id.co.swipepay.apigateway.filter.JwtTokenAuthenticationFilter;
import id.co.swipepay.apigateway.repository.UserTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;

/**
 * Config role-based auth.
 *
 * @author shuaicj 2017/10/18
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtAuthenticationConfig config;

    @Autowired
    private UserTokenRepository tokenRepository;

    @Bean
    public JwtAuthenticationConfig jwtConfig() {
        return new JwtAuthenticationConfig();
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf().disable()
                .logout().disable()
                .formLogin().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                    .anonymous()
                .and()
                    .exceptionHandling().authenticationEntryPoint(
                            (req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                    .addFilterBefore(new JwtTokenAuthenticationFilter(config, tokenRepository),
                            UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests()
                    .antMatchers(config.getUrl()).permitAll()
                    .antMatchers("/actuator/health").permitAll()
                    .antMatchers("/user/v1/login/**").permitAll()
                    .antMatchers("/pos/v1/**").hasAuthority("USER")
                    .antMatchers("/settlement/v1/**").hasAuthority("USER")
                    .anyRequest().authenticated();
    }
}

