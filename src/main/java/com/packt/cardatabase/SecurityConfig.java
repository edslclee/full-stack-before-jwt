package com.packt.cardatabase;

import com.packt.cardatabase.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder());
    }

    //Filter적용
    @Autowired
    private AuthenticationFilter authenticationFilter;

    //예외처리적용
    @Autowired
    private AuthEntryPoint exceptionHandler;

    //Bean for AuthenticationManager(JWT-LoginController)
    @Bean
    public AuthenticationManager getAuthenticationManager() throws Exception {
        return  authenticationManager();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //cors() function add
        http.csrf().disable().cors().and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeRequests()
                // POST request to /login endpoint is not secured
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                // All other requests are secured
                .anyRequest().authenticated().and()
                // exception handling
                .exceptionHandling()
                .authenticationEntryPoint(exceptionHandler).and()
                //filter add
                .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }
    // Add Global CORS filter inside the class
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        //localhost:3000 is allowed
        //config.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
        config.setAllowedOrigins(Arrays.asList("*"));
        config.setAllowedMethods(Arrays.asList("*"));
        config.setAllowedHeaders(Arrays.asList("*"));
        config.setAllowCredentials(false);
        config.applyPermitDefaultValues();

        source.registerCorsConfiguration("/**", config);
        return source;
    }


}
