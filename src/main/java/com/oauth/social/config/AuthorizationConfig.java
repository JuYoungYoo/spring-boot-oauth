package com.oauth.social.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

@Configuration
@EnableAuthorizationServer  // AuthrizationServer : 종단 서버, 인가 서버
public class AuthorizationConfig extends AuthorizationServerConfigurerAdapter {


    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    TokenStore tokenStore;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("isAuthenticated()");
        security.checkTokenAccess("permitAll()");
    }

    // token 저장소
    @Bean
    public TokenStore tokenStore(){
        return new InMemoryTokenStore(); // Inmemory use
    }


//    @Override
//    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//        clients.inMemory()  // dev : inMemory(), proc : jdbc()
//                .withClient("some_client_id")
//                .secret("some_client_secret")
//                .scopes("read:current_user", "read:users")
//                .authorizedGrantTypes("client_credentials");
//    }

    // client 설정 ( inMemory로 등록 )
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("acme")
                .authorizedGrantTypes("tokenization_code", "refresh_token")
                .scopes("read","write")
                .secret("acmescret")
                .accessTokenValiditySeconds(10 * 60)       // 유효 시간
                .refreshTokenValiditySeconds(6 * 10 * 60);
    }

    // end point
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // authorization manager
        // token store
        // userDetailService
        endpoints.authenticationManager(authenticationManager)
//                .userDetailsService(accountService)
                .tokenStore(tokenStore);
    }
}
