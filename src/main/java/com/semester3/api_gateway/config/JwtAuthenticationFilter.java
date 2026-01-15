package com.semester3.api_gateway.config;

import com.semester3.api_gateway.util.JwtUtil;
import org.apache.http.HttpHeaders;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter implements GlobalFilter {
    private final JwtUtil jwtUtil;

    public JwtAuthenticationFilter(JwtUtil jwtUtil){
        this.jwtUtil = jwtUtil;
    }
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain){
        ServerHttpRequest request = exchange.getRequest();
        if(request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
            String authHeader =
                    request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if(authHeader != null && authHeader.startsWith("Bearer")){
                String token = authHeader.substring(7);
                if(!jwtUtil.validateToken(token)){
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }
            }
        }
        return chain.filter(exchange);
    }

}
