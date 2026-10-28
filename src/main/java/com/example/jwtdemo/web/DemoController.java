package com.example.jwtdemo.web;

import com.example.jwtdemo.service.ExternalApiService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/demo")
public class DemoController {

    private final ExternalApiService externalApiService;

    public DemoController(ExternalApiService externalApiService) {
        this.externalApiService = externalApiService;
    }

    @GetMapping("/call-user/{id}")
    public String callUserService(@PathVariable String id) {
        return externalApiService.callExternalService(id);
    }
}
