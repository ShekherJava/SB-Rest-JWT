package com.example.demo.security;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.demo.filter.JwtFilter;

@Configuration
@EnableWebSecurity
public class MyAppSecurityConfiguration {
	
	@Autowired
	UserDetailsService customUserDetailsService;
	
	@Autowired
	BCryptPasswordEncoder passwordEncoder;
	
	@Autowired
	JwtFilter jwtFilter;
	
	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		http.authorizeHttpRequests(
				authorize -> authorize.requestMatchers("/auth/login")
                                      .permitAll() 
				                      .requestMatchers("/**")
				                      .hasAnyRole("ADMIN")
				).httpBasic(withDefaults());
		http.csrf(csrf -> csrf.disable());
		http.sessionManagement(config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		
		http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
		
		return  http.build();
	}
	
	/*
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder  auth) throws Exception {
		auth.jdbcAuthentication()
		    .dataSource(dataSource)
		    .passwordEncoder(passwordEncoder);
	}
	*/
	
	
	@Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
		
        AuthenticationManagerBuilder authenticationManagerBuilder = 
                http.getSharedObject(AuthenticationManagerBuilder.class);
        
        authenticationManagerBuilder.userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder);
        return authenticationManagerBuilder.build();
    }
    

}
