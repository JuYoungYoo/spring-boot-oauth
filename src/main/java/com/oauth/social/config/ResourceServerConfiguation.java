package com.oauth.social.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

@EnableResourceServer
public class ResourceServerConfiguation extends ResourceServerConfigurerAdapter{

    // resource server ( default order(3) )
        @Override
        public void configure(HttpSecurity http) throws Exception {
            // @formatter:off

            http.anonymous()
                    .and()
                    .formLogin()
                    .and()
                    .antMatcher("/me")
                    .authorizeRequests()
                    .anyRequest()
                    .authenticated();
//            http.antMatcher("/me").authorizeRequests().anyRequest().authenticated();
//            http.requestMatchers().antMatchers("/","/me", "/oauth/**")
            // @formatter:on
        }
}
