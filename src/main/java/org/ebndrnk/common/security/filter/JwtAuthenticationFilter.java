package org.ebndrnk.common.security.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String[] WHITELIST = new String[]{
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/actuator/**"
    };


    private final JwtTokenValidator jwtTokenValidator;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        String method = request.getMethod();

        log.info("Incoming request: {} {}", method, path);

        for (String publicPath : WHITELIST) {
            if (path.startsWith(publicPath.replace("/**", ""))) {
                log.info("Public path, skipping JWT validation: {}", path);
                filterChain.doFilter(request, response);
                return;
            }
        }


        if (HttpMethod.OPTIONS.matches(method)) {
            log.info("OPTIONS request, skipping JWT validation: {}", path);
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");
        log.info("Authorization header: {}", authHeader);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("JWT token is missing or invalid for path {}!", path);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "JWT token is missing or invalid!");
            return;
        }

        String token = authHeader.substring(7);

        try {
            Claims claims = jwtTokenValidator.validateToken(token);
            String email = claims.getSubject();
            String role = claims.get("role", String.class);

            log.info("JWT valid. User: {}, Role: {}", email, role);

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            email, null,
                            List.of(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                    );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            filterChain.doFilter(request, response);

        } catch (JwtException e) {
            log.warn("Invalid JWT token for path {}: {}", path, e.getMessage());
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid JWT token!");
        } catch (Exception e) {
            log.error("Unexpected error during JWT validation for path {}: {}", path, e.getMessage(), e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal server error");
        }
    }
}
