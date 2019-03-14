package com.example.multipleoauthclients.infrastructure.security;

import io.restassured.RestAssured;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@RunWith(SpringRunner.class)
public class SecurityTest {
    @LocalServerPort
    private int serverport;

    @Before
    public void setup() {
        RestAssured.port = serverport;
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
    }

    /**
     * The business logic is that administrator accounts should only
     * use the angular app to log on. So using the Angular client id/secret,
     * we should get a valid token back.
     */
    @Test
    public void testLoginAsAdministratorWithCorrectClient() {
        RestAssured.given()
                   .auth().preemptive().basic("angular_app_id", "angular_app_secret")
                   .header("Content-Type", "application/x-www-form-urlencoded")
                   .header("Accept", "application/json")
                   .formParam("grant_type", "password")
                   .formParam("client_id", "angular_app_id")
                   .formParam("client_secret", "angular_app_secret")
                   .formParam("username", "admin@example.com")
                   .formParam("password", "pwd-admin")
                   .post("/oauth/token")
                   .then()
                   .statusCode(HttpStatus.OK.value());
    }

    /**
     * This test validates if an administrator account tries to get
     * an access token through the mobile client, no access token
     * should be granted (as we want admins to use the angular app only)
     */
    @Test
    public void testLoginAsAdministratorWithWrongClient() {
        RestAssured.given()
                   .auth().preemptive().basic("mobile_client_id", "mobile_client_secret")
                   .header("Content-Type", "application/x-www-form-urlencoded")
                   .header("Accept", "application/json")
                   .formParam("grant_type", "password")
                   .formParam("client_id", "mobile_client_id")
                   .formParam("client_secret", "mobile_client_secret")
                   .formParam("username", "admin@example.com")
                   .formParam("password", "pwd-admin")
                   .post("/oauth/token")
                   .then()
                   .statusCode(HttpStatus.FORBIDDEN.value());
    }
}
