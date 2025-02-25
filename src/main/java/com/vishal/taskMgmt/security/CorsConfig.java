package com.vishal.taskMgmt.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig implements WebMvcConfigurer {
 @Override
 public void addCorsMappings(CorsRegistry registry) {
     registry.addMapping("/**") // Allow all endpoints
             .allowedOrigins("http://localhost:4200") // Allow Angular app origin
             .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // Allowed HTTP methods
             .allowedHeaders("*") // Allow all headers
             .allowCredentials(true); // Allow cookies/auth headers if needed
 }
}
