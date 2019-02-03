package com.example.multipleoauthclients.infrastructure.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

import java.util.Map;

@Configuration
public class OAuth2ServerConfiguration {

    private static final String RESOURCE_ID = "application-service";

    @Configuration
    @EnableResourceServer
    @EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

        @Override
        public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
            resources.resourceId(RESOURCE_ID);
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {

            http.authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS, "/api/**").permitAll()
                .and()
                .antMatcher("/api/**")
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/api/users").permitAll()
                .anyRequest().authenticated();
        }
    }

    @Configuration
    @EnableAuthorizationServer
    protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

        private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationServerConfiguration.class);

        @Autowired
        private AuthenticationManager authenticationManager;

        @Autowired
        private UserDetailsService userDetailsService;

        @Autowired
        private PasswordEncoder passwordEncoder;

        @Autowired
        private TokenStore tokenStore;
        @Autowired
        private ClientDetailsService clientDetailsService;

        @Override
        public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
            security.passwordEncoder(passwordEncoder);
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.inMemory()
                   .withClient("mobile_client_id")
                   .authorizedGrantTypes("password", "refresh_token")
                   .scopes("mobile_app")
                   .resourceIds(RESOURCE_ID)
                   .secret(passwordEncoder.encode("mobile_client_secret"))
                   .and()
                   .withClient("angular_app_id")
                   .authorizedGrantTypes("password", "refresh_token")
                   .scopes("angular_app")
                   .resourceIds(RESOURCE_ID)
                   .secret(passwordEncoder.encode("angular_app_secret"));
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints.tokenStore(tokenStore)
                     .authenticationManager(authenticationManager)
                     .userDetailsService(userDetailsService)
                     .tokenServices(tokenServices());
        }

        @Bean
        public AuthorizationServerTokenServices tokenServices() {
            DefaultTokenServices tokenServices = new DefaultTokenServices();
            tokenServices.setClientDetailsService(clientDetailsService);
            tokenServices.setSupportRefreshToken(true);
            tokenServices.setTokenStore(tokenStore);
//           TODO needed if I don't use JWT? tokenServices.setTokenEnhancer();
            tokenServices.setAuthenticationManager(authenticationManager);

            return new AuthorizationServerTokenServices() {
                @Override
                public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
                    UsernamePasswordAuthenticationToken userAuthentication =
                            (UsernamePasswordAuthenticationToken) authentication.getUserAuthentication();
                    ApplicationUserDetails userDetails = (ApplicationUserDetails) userAuthentication.getPrincipal();

                    Map clientDetails = (Map) userAuthentication.getDetails();
                    String clientId = (String) clientDetails.get("client_id");

                    // Post-authentication callback
                    // TODO Validate/authenticate user and/or client

                    LOGGER.info("username: {}", userDetails.getUsername());
                    LOGGER.info("clientId: {}", clientId);

                    if (userDetails.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMINISTRATOR"))
                            && !clientId.equals("angular_app_id")) {
                        LOGGER.info("ADMIN trying to log on via wrong client!");
                        authentication.setAuthenticated(false);
                    }

                    return tokenServices.createAccessToken(authentication);
                }

                @Override
                public OAuth2AccessToken refreshAccessToken(String refreshToken, TokenRequest tokenRequest) throws AuthenticationException {
                    return tokenServices.refreshAccessToken(refreshToken, tokenRequest);
                }

                @Override
                public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
                    return tokenServices.getAccessToken(authentication);
                }
            };
        }
    }

    @Configuration
    public static class WebSecurityGlobalConfig extends WebSecurityConfigurerAdapter {

        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean() throws Exception {
            return super.authenticationManagerBean();
        }

    }
}
