package net.samsungds.ees.infra.api.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class GatewayConfig {
    @Value("${your-provider.jwk-set-uri}")
    private String jwkSetUri;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf().disable()
                .authorizeExchange()
                .pathMatchers("/login").permitAll()
                .anyExchange().authenticated()
                .and()
                .oauth2Login()
                .and()
                .oauth2ResourceServer()
                .jwt()
                .jwtDecoder(jwtDecoder())
                .and().and()
                .build();
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        NimbusReactiveJwtDecoder jwtDecoder = (NimbusReactiveJwtDecoder) ReactiveJwtDecoders.fromOidcIssuerLocation(jwkSetUri);
        jwtDecoder.setClaimSetConverter(new CustomClaimSetConverter());
        return jwtDecoder;
    }

    private static class CustomClaimSetConverter implements Converter<Map<String, Object>, Map<String, Object>> {
        @Override
        public Map<String, Object> convert(Map<String, Object> claims) {
            Map<String, Object> convertedClaims = new HashMap<>();
            convertedClaims.put("sub", claims.get("sub"));
            convertedClaims.put("name", claims.get("name"));
            convertedClaims.put("email", claims.get("email"));
            convertedClaims.put("roles", claims.get("roles"));
            return convertedClaims;
        }
    }
}
