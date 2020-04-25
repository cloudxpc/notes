# OAuth 2.0 Resource Server

spring security验证请求头中OAuth2.0 Bearer Token来保护资源，支持两种形式：

- JWT
- Opaque Tokens

请求：

```
GET / HTTP/1.1
Authorization: Bearer some-token-value # Resource Server will process this
```

使用Spring Boot时引用的包：

```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

当配置如下时：

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://idp.example.com/issuer
```

`https://idp.example.com/issuer`会被添加到jwt token的 `iss` claim中，resource server会根据这个地址自动配置。

而authorization server需要配置以下任一地址：

```
https://idp.example.com/issuer/.well-known/openid-configuration
https://idp.example.com/.well-known/openid-configuration/issuer
https://idp.example.com/.well-known/oauth-authorization-server/issuer
```

地址需要配置在下面的endpoint：

- Provider Configuration endpoint (OpenID Connect)
- Authorization Server Metadata endpoint (OAuth2)

当resource server检测到一个bearer token时，会做如下操作：

1. Validate its signature against a public key obtained from the `jwks_url` endpoint during startup and matched against the JWT
2. Validate the JWT’s `exp` and `nbf` timestamps and the JWT’s `iss` claim, and
3. Map each scope to an authority with the prefix `SCOPE_`.

### Specifying the Authorization Server JWK Set Uri Directly

当自动配置不适用时，可以手动配置jwk：

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://idp.example.com
          jwk-set-uri: https://idp.example.com/.well-known/jwks.json
```

指定了`jwk-set-uri`后resource server在启动时就不会再尝试连接authorization server了，这里仍然指定了`issuer-uri`所以resource server仍会验证每个jwt中的`iss` claim

### Spring Boot Configuration

在spring boot程序中，两个`@Bean`用于配置resource server。第一个是`WebSecurityConfigurerAdapter`，默认配置如下：

```java
protected void configure(HttpSecurity http) {
    http
        .authorizeRequests(authorize -> authorize
            .anyRequest().authenticated()
        )
        .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
}
```

- 如果程序中没有`WebSecurityConfigurerAdapter`，那么默认应用上面的配置

自定义：

```java
@EnableWebSecurity
public class MyCustomSecurityConfiguration extends WebSecurityConfigurerAdapter {
    protected void configure(HttpSecurity http) {
        http
            .authorizeRequests(authorize -> authorize
                .mvcMatchers("/messages/**").hasAuthority("SCOPE_message:read")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(myConverter())
                )
            );
    }
}
```

另一个`@Bean`是`JwtDecoder`，用于将string类型的token解码成`Jwt`对象

```java
@Bean
public JwtDecoder jwtDecoder() {
    return JwtDecoders.fromIssuerLocation(issuerUri);
}
```

- 如果程序中没有`JwtDecoder`，那么默认应用上面的配置

DSL配置`jwkSetUri()`：

```java
@EnableWebSecurity
public class DirectlyConfiguredJwkSetUri extends WebSecurityConfigurerAdapter {
    protected void configure(HttpSecurity http) {
        http
            .authorizeRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwkSetUri("https://idp.example.com/.well-known/jwks.json")
                )
            );
    }
}
```

`decoder()`可以更深入的配置`JwtDecoder`:

```java
@EnableWebSecurity
public class DirectlyConfiguredJwtDecoder extends WebSecurityConfigurerAdapter {
    protected void configure(HttpSecurity http) {
        http
            .authorizeRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(myCustomDecoder())
                )
            );
    }
}
```

或者配置一个`JwtDecoder` `@Bean`，效果和`decoder()`一样：

```java
@Bean
public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
}
```

### Configuring Trusted Algorithms

spring boot默认加密解密算法是`RS256`，更改算法的配置：

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jws-algorithm: RS512
          jwk-set-uri: https://idp.example.org/.well-known/jwks.json
```

使用Builder:

```java
@Bean
JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.fromJwkSetUri(this.jwkSetUri)
            .jwsAlgorithm(RS512).build();
}
```

多个algorithm:

```java
@Bean
JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.fromJwkSetUri(this.jwkSetUri)
            .jwsAlgorithm(RS512).jwsAlgorithm(EC512).build();
}
```

```java
@Bean
JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.fromJwkSetUri(this.jwkSetUri)
            .jwsAlgorithms(algorithms -> {
                    algorithms.add(RS512);
                    algorithms.add(EC512);
            }).build();
}
```

spring security的jwt基于Nimbus，它有一个`JWSKeySelector`实现，可以根据JWK Set URI的response来选择不同的algorithm

```java
@Bean
public JwtDecoder jwtDecoder() {
    // makes a request to the JWK Set endpoint
    JWSKeySelector<SecurityContext> jwsKeySelector =
            JWSAlgorithmFamilyJWSKeySelector.fromJWKSetURL(this.jwkSetUrl);

    DefaultJWTProcessor<SecurityContext> jwtProcessor =
            new DefaultJWTProcessor<>();
    jwtProcessor.setJWSKeySelector(jwsKeySelector);

    return new NimbusJwtDecoder(jwtProcessor);
}
```

### Trusting a Single Asymmetric Key

如果resource server不使用JWK Set endpoint的话，可以指定RSA public key

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          public-key-location: classpath:my-key.pub
```

Builder:

```java
@Bean
public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withPublicKey(this.key).build();
}
```

### Trusting a Single Symmetric Key

```java
@Bean
public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withSecretKey(this.key).build();
}
```

### Configuring Authorization

Authorization Server发行的JWT一般包含`scope`或者`scp`属性

```
{ …, "scope" : "messages contacts"}
```

Resource Server会尝试将这些scope转换为authories，使用前缀"SCOPE_"标注。所以配置的时候需要加上前缀：

```java
@EnableWebSecurity
public class DirectlyConfiguredJwkSetUri extends WebSecurityConfigurerAdapter {
    protected void configure(HttpSecurity http) {
        http
            .authorizeRequests(authorize -> authorize
                .mvcMatchers("/contacts/**").hasAuthority("SCOPE_contacts")
                .mvcMatchers("/messages/**").hasAuthority("SCOPE_messages")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
    }
}
```

或是

```java
@PreAuthorize("hasAuthority('SCOPE_messages')")
public List<Message> getMessages(...) {}
```

**Extracting Authorities Manually**

有时这种前缀并不适用，需要手动配置如何从jwt中提取authories。`JwtAuthenticationConverter`负责将jwt转换为authentication，配置如下：

```java
@EnableWebSecurity
public class CustomAuthoritiesClaimName extends WebSecurityConfigurerAdapter {
    protected void configure(HttpSecurity http) {
        http
            .authorizeRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            );
    }
}

JwtAuthenticationConverter jwtAuthenticationConverter() {
    JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    grantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");

    JwtAuthenticationConverter authenticationConverter = new JwtAuthenticationConverter();
    jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
    return jwtAuthenticationConverter;
}
```

- 这里假设权限是放在jwt中名为authorities的claim中

修改前缀：

```java
JwtAuthenticationConverter jwtAuthenticationConverter() {
    JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

    JwtAuthenticationConverter authenticationConverter = new JwtAuthenticationConverter();
    jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
    return jwtAuthenticationConverter;
}
```

如更复杂的情况，可以自定义一个`Converter<Jwt, AbstractAuthenticationToken>`:

```java
static class CustomAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    public AbstractAuthenticationToken convert(Jwt jwt) {
        return new CustomAuthenticationToken(jwt);
    }
}
```

### Configuring Validation

resource server提供了两个标准的validator和一个自定义`OAuth2TokenValidator`。

**自定义Timestamp Validation**

resource server使用`JwtTimestampValidator`来验证有效时间窗口。

```java
@Bean
JwtDecoder jwtDecoder() {
     NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder)
             JwtDecoders.fromIssuerLocation(issuerUri);

     OAuth2TokenValidator<Jwt> withClockSkew = new DelegatingOAuth2TokenValidator<>(
            new JwtTimestampValidator(Duration.ofSeconds(60)),
            new IssuerValidator(issuerUri));

     jwtDecoder.setJwtValidator(withClockSkew);

     return jwtDecoder;
}
```

**自定义validator**

检查`aud`claim:

```java
OAuth2TokenValidator<Jwt> audienceValidator() {
    return new JwtClaimValidator<List<String>>(AUD, aud -> aud.contains("messaging"));
}
```

或者实现接口：

```java
static class AudienceValidator implements OAuth2TokenValidator<Jwt> {
    OAuth2Error error = new OAuth2Error("custom_code", "Custom error message", null);

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        if (jwt.getAudience().contains("messaging")) {
            return OAuth2TokenValidatorResult.success();
        } else {
            return OAuth2TokenValidatorResult.failure(error);
        }
    }
}

// ...

OAuth2TokenValidator<Jwt> audienceValidator() {
    return new AudienceValidator();
}
```

配置：

```java
@Bean
JwtDecoder jwtDecoder() {
    NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder)
        JwtDecoders.fromIssuerLocation(issuerUri);

    OAuth2TokenValidator<Jwt> audienceValidator = audienceValidator();
    OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
    OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator);

    jwtDecoder.setJwtValidator(withAudience);

    return jwtDecoder;
}
```

### Configuring Claim Set Mapping

spring security使用Nimbus library来解析验证jwt。有些情况需要自定义如何将jwt的字段转换为java类型。resource server提供`MappedJwtClaimSetConverter`来支持该操作。

默认情况下，`MappedJwtClaimSetConverter`使用以下规则转换claim

| Claim | Java Type    |
| ----- | ------------ |
| `aud` | `Collection` |
| `exp` | `Instant`    |
| `iat` | `Instant`    |
| `iss` | `String`     |
| `jti` | `String`     |
| `nbf` | `Instant`    |
| `sub` | `String`     |

使用`MappedJwtClaimSetConverter.withDefaults`来定义转换：

```java
@Bean
JwtDecoder jwtDecoder() {
    NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();

    MappedJwtClaimSetConverter converter = MappedJwtClaimSetConverter
            .withDefaults(Collections.singletonMap("sub", this::lookupUserIdBySub));
    jwtDecoder.setClaimSetConverter(converter);

    return jwtDecoder;
}
```

添加claim:

```java
MappedJwtClaimSetConverter.withDefaults(Collections.singletonMap("custom", custom -> "value"));
```

删除claim:

```java
MappedJwtClaimSetConverter.withDefaults(Collections.singletonMap("legacyclaim", legacy -> null));
```

更复杂的转换可以提供自定义的`Converter<Map<String, Object>, Map<String,Object>>`:

```java
public class UsernameSubClaimAdapter implements Converter<Map<String, Object>, Map<String, Object>> {
    private final MappedJwtClaimSetConverter delegate =
            MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());

    public Map<String, Object> convert(Map<String, Object> claims) {
        Map<String, Object> convertedClaims = this.delegate.convert(claims);

        String username = (String) convertedClaims.get("user_name");
        convertedClaims.put("sub", username);

        return convertedClaims;
    }
}
```

应用：

```java
@Bean
JwtDecoder jwtDecoder() {
    NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    jwtDecoder.setClaimSetConverter(new UsernameSubClaimAdapter());
    return jwtDecoder;
}
```

### Configuring Timeouts

resource server连接authorization server的默认超时时间为30s。通过设置`NimbusJwtDecoder`的`RestOperations`来自定义：

```java
@Bean
public JwtDecoder jwtDecoder(RestTemplateBuilder builder) {
    RestOperations rest = builder
            .setConnectionTimeout(60000)
            .setReadTimeout(60000)
            .build();

    NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).restOperations(rest).build();
    return jwtDecoder;
}
```

### Configuration for Introspection - Opaque Token

**Post-Authentication**

当token验证通过后，`BearerTokenAuthentication`实例会被设置在`SecurityContext`中。所以可以在`@Controller`中访问：

```java
@GetMapping("/foo")
public String foo(BearerTokenAuthentication authentication) {
    return authentication.getTokenAttributes().get("sub") + " is the subject";
}
```

`BearerTokenAuthentication`持有一个`OAuth2AuthenticatedPrincipal`，所以也可这么使用：

```java
@GetMapping("/foo")
public String foo(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
    return principal.getAttribute("sub") + " is the subject";
}
```

**Looking Up Attributes Via SpEL**

也可以使用SpEL来获取jwt属性：

```java
@PreAuthorize("principal?.attributes['sub'] == 'foo'")
public String forFoosEyesOnly() {
    return "foo";
}
```

- 使用`@EnableGlobalMethodSecurity`开启

### Bearer Token Resolution

默认情况下，resource server从请求头的`Authorization`字段读取bearer token。

**Reading the Bearer Token from a Custom Header**

如果想从一个自定义的字段中读取，用DSL进行配置：

```java
http
    .oauth2ResourceServer(oauth2 -> oauth2
        .bearerTokenResolver(new HeaderBearerTokenResolver("x-goog-iap-jwt-assertion"))
    );
```

**Reading the Bearer Token from a Form Parameter**

如果想从form中读取token，配置`DefaultBearerTokenResolver`:

```java
DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
resolver.setAllowFormEncodedBodyParameter(true);
http
    .oauth2ResourceServer(oauth2 -> oauth2
        .bearerTokenResolver(resolver)
    );
```

### Bearer Token Propagation

如果当前resource server已经验证了token，那么想把它传给下游服务，可以使用`ServletBearerExchangeFilterFunction`

```java
@Bean
public WebClient rest() {
    return WebClient.builder()
            .filter(new ServletBearerExchangeFilterFunction())
            .build();
}
```

如此配置后，spring security将查找当前`Authentication`，提取`AbstractOAuth2Token`，然后放在`Authorization`头中。例如：

```java
this.rest.get()
        .uri("https://other-service.example.com/endpoint")
        .retrieve()
        .bodyToMono(String.class)
        .block()
```

当访问地址时，`Authorization`请求头会自动填入token。当自定义header时：

```java
this.rest.get()
        .uri("https://other-service.example.com/endpoint")
        .headers(headers -> headers.setBearerAuth(overridingToken))
        .retrieve()
        .bodyToMono(String.class)
        .block()
```

**`RestTemplate` support**

目前没有等价的`ServletBearerExchangeFilterFunction`提供给`RestTemplate`使用，但可自行获取：

```java
@Bean
RestTemplate rest() {
    RestTemplate rest = new RestTemplate();
    rest.getInterceptors().add((request, body, execution) -> {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return execution.execute(request, body);
        }

        if (!(authentication.getCredentials() instanceof AbstractOAuth2Token)) {
            return execution.execute(request, body);
        }

        AbstractOAuth2Token token = (AbstractOAuth2Token) authentication.getCredentials();
        request.getHeaders().setBearerAuth(token.getTokenValue());
        return execution.execute(request, body);
    });
    return rest;
}
```

### Bearer Token Failure

当token无效时，resource server会抛出`InvalidBearerTokenException`异常，导致的error response:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error_code="invalid_token", error_description="Unsupported algorithm of none", error_uri="https://tools.ietf.org/html/rfc6750#section-3.1"
```

另外，它还会触发`AuthenticationFailureBadCredentialsEvent`事件，可以程序中监听：

```java
@Component
public class FailureEvents {
    @EventListener
    public void onFailure(AuthenticationFailureEvent failure) {
        if (badCredentials.getAuthentication() instanceof BearerTokenAuthenticationToken) {
            // ... handle
        }
    }
}
```

