# OAuth 2.0 Client

Spring Security对OAuth2四个角色中的Client提供了支持

#### Spring Boot support for OAuth2 client

Spring Boot程序中需要引入以下包来支持OAuth2 Client

```xml
<dependency>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
```

### ClientRegistration

表示一个客户端(Client)配置对象，是在OAuth2 provider或是OpenID Connect 1.0 provider注册的。定义如下：

```java
public final class ClientRegistration {
    private String registrationId;  
    private String clientId;    
    private String clientSecret;    
    private ClientAuthenticationMethod clientAuthenticationMethod;  
    private AuthorizationGrantType authorizationGrantType;  
    private String redirectUriTemplate;
    private Set<String> scopes;
    private ProviderDetails providerDetails;
    private String clientName;  

    public class ProviderDetails {
        private String authorizationUri;    
        private String tokenUri;    
        private UserInfoEndpoint userInfoEndpoint;
        private String jwkSetUri;   
        private Map<String, Object> configurationMetadata;  

        public class UserInfoEndpoint {
            private String uri;
            private AuthenticationMethod authenticationMethod;  
            private String userNameAttributeName;   

        }
    }
}
```

- `registrationId`：唯一ID
- `clientId`：客户端ID
- `clientSecret`：客户端密钥
- `clientAuthenticationMethod`：验证方式，支持basic，post和none(public clients)
- `authorizationGrantType`：授权方式，OAuth2定义了四种授权方式，这里支持authorization_code，client_credentials和password
- `redirectUriTemplate`：验证或授权成功后的返回地址
- `scopes`：客户端请求的内容
- `clientName`：描述性名称，会显示在自动生成的登录页面
- `authorizationUri`：Authorization Server的授权地址
- `tokenUri`：Authorization Server的令牌地址
- `jwkSetUri`：Authorization Server上获取JWK的地址
- `configurationMetadata`：OpenID Provider Configuration Information.
- `(userInfoEndpoint)uri`：UserInfo地址
- `(userInfoEndpoint)authenticationMethod`：请求UserInfo时的验证方式，支持header，form和query
- `userNameAttributeName`：UserInfo返回信息中的名称属性，表示用户的用户名

如果配置了OpenID Connect Provider’s Configuration endpoint或者Authorization Server’s Metadata endpoint，`ClientRegistration`可以通过请求这个地址来初始化。可以调用`ClientRegistrations`类的方法：

```java
ClientRegistration clientRegistration = ClientRegistrations.fromIssuerLocation("https://idp.example.com/issuer").build();
```

这段代码会以先后顺序请求以下地址，如果某个地址返回200则停止。

```
https://idp.example.com/issuer/.well-known/openid-configuration
https://idp.example.com/.well-known/openid-configuration/issuer
https://idp.example.com/.well-known/oauth-authorization-server/issuer
```

### ClientRegistrationRepository

`ClientRegistration`仓库，存放`ClientRegistration`的类。

Spring boot会将所有`spring.security.oauth2.client.registration.[registrationId]`的配置组装成`ClientRegistration`，然后把这些`ClientRegistration`再组装成一个`ClientRegistrationRepository`。并且它是一个`@Bean`，需要时可以获得:

```java
@Autowired
private ClientRegistrationRepository clientRegistrationRepository;
```

- 默认实现: `InMemoryClientRegistrationRepository`

### OAuth2AuthorizedClient

`OAuth2AuthorizedClient`用于表示一个已授权的客户端，它存储：

- `ClientRegistration`
- `principalName`
- `OAuth2AccessToken`
- `OAuth2RefreshToken`

### OAuth2AuthorizedClientRepository / OAuth2AuthorizedClientService

`OAuth2AuthorizedClientRepository`用于持久化`OAuth2AuthorizedClient`，`OAuth2AuthorizedClientService`用于在整个应用程序中管理`OAuth2AuthorizedClient`。这两个类主要用于获取`OAuth2AuthorizedClient`当中的`OAuth2AccessToken`。

```java
@Controller
public class OAuth2ClientController {

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/")
    public String index(Authentication authentication) {
        OAuth2AuthorizedClient authorizedClient =
            this.authorizedClientService.loadAuthorizedClient("okta", authentication.getName());

        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();

        ...

        return "index";
    }
}
```

- `OAuth2AuthorizedClientService`默认实现：`InMemoryOAuth2AuthorizedClientService`

### OAuth2AuthorizedClientManager / OAuth2AuthorizedClientProvider

`OAuth2AuthorizedClientManager`用来管理和创建`OAuth2AuthorizedClient`

- 调用`OAuth2AuthorizedClientProvider`来创建`OAuth2AuthorizedClient`
- 调用`OAuth2AuthorizedClientService`或`OAuth2AuthorizedClientRepository`来保存`OAuth2AuthorizedClient`
- 委托给`OAuth2AuthorizationSuccessHandler`或`OAuth2AuthorizationFailureHandler`来处理授权成功或失败。

`OAuth2AuthorizedClientProvider`用于执行具体的授权操作。`OAuth2AuthorizedClientProviderBuilder`用于构建`OAuth2AuthorizedClientProvider`。

配置一个`OAuth2AuthorizedClientProvider`：

```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
        ClientRegistrationRepository clientRegistrationRepository,
        OAuth2AuthorizedClientRepository authorizedClientRepository) {

    OAuth2AuthorizedClientProvider authorizedClientProvider =
            OAuth2AuthorizedClientProviderBuilder.builder()
                    .authorizationCode()
                    .refreshToken()
                    .clientCredentials()
                    .password()
                    .build();

    DefaultOAuth2AuthorizedClientManager authorizedClientManager =
            new DefaultOAuth2AuthorizedClientManager(
                    clientRegistrationRepository, authorizedClientRepository);
    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

    return authorizedClientManager;
}
```

当尝试验证授权通过，`DefaultOAuth2AuthorizedClientManager`会交由`OAuth2AuthorizationSuccessHandler`处理成功之后的操作。`OAuth2AuthorizationSuccessHandler`会调用`OAuth2AuthorizedClientRepository`来保存`OAuth2AuthorizedClient`。

定义成功或失败处理行为：

- `setAuthorizationSuccessHandler(OAuth2AuthorizationSuccessHandler)`
- `setAuthorizationFailureHandler(OAuth2AuthorizationFailureHandler)`

`DefaultOAuth2AuthorizedClientManager`应该在有`HttpServletRequest`的环境中使用，如果在没有`HttpServletRequest`的环境，应当使用`AuthorizedClientServiceOAuth2AuthorizedClientManager`。如，service application一般使用`AuthorizedClientServiceOAuth2AuthorizedClientManager`来做验证授权，并且可以考虑使用`client_credentials`模式。

```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
        ClientRegistrationRepository clientRegistrationRepository,
        OAuth2AuthorizedClientService authorizedClientService) {

    OAuth2AuthorizedClientProvider authorizedClientProvider =
            OAuth2AuthorizedClientProviderBuilder.builder()
                    .clientCredentials()
                    .build();

    AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager =
            new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                    clientRegistrationRepository, authorizedClientService);
    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

    return authorizedClientManager;
}
```

- `OAuth2AuthorizedClientManager`的默认实现：`DefaultOAuth2AuthorizedClientManager`

### Authorization Grant Support

#### Authorization Code

**初始化Authorization Request**

`OAuth2AuthorizationRequestRedirectFilter`调用`OAuth2AuthorizationRequestResolver`来生成`OAuth2AuthorizationRequest`开启Authorization Code的验证流程。

- `OAuth2AuthorizationRequestResolver`的默认实现：`DefaultOAuth2AuthorizationRequestResolver`

`DefaultOAuth2AuthorizationRequestResolver`默认匹配`/oauth2/authorization/{registrationId}`这个路径，提取`registrationId`，根据`ClientRegistration`来生成`OAuth2AuthorizationRequest`。

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          okta:
            client-id: okta-client-id
            client-secret: okta-client-secret
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/authorized/okta"
            scope: read, write
        provider:
          okta:
            authorization-uri: https://dev-1234.oktapreview.com/oauth2/v1/authorize
            token-uri: https://dev-1234.oktapreview.com/oauth2/v1/token
```

`URI` template variables：

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          okta:
            ...
            redirect-uri: "{baseScheme}://{baseHost}{basePort}{basePath}/authorized/{registrationId}"
            ...
```

- `{baseUrl}` 表示 `{baseScheme}://{baseHost}{basePort}{basePath}`
- 在代理环境中，模板变量还可以确保应用`X-Forwarded-*`的值

**自定义Authorization Request - OAuth2AuthorizationRequestResolver**

添加附加参数：

```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .authorizationEndpoint(authorization -> authorization
                    .authorizationRequestResolver(
                        authorizationRequestResolver(this.clientRegistrationRepository)
                    )
                )
            );
    }

    private OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {

        DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository, "/oauth2/authorization");
        authorizationRequestResolver.setAuthorizationRequestCustomizer(
                authorizationRequestCustomizer());

        return  authorizationRequestResolver;
    }

    private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {
        return customizer -> customizer
                    .additionalParameters(params -> params.put("prompt", "consent"));
    }
}
```

附加参数还可以加在：

```yaml
spring:
  security:
    oauth2:
      client:
        provider:
          okta:
            authorization-uri: https://dev-1234.oktapreview.com/oauth2/v1/authorize?prompt=consent
```

**保存Authorization Request - AuthorizationRequestRepository**

用于保存`OAuth2AuthorizationRequest`，从初始化直到接收到响应。保存的`OAuth2AuthorizationRequest`用来验证Authorization Response的合法性。

自定义:

```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .oauth2Client(oauth2 -> oauth2
                .authorizationCodeGrant(codeGrant -> codeGrant
                    .authorizationRequestRepository(this.authorizationRequestRepository())
                    ...
                )
            );
    }
}
```

- `AuthorizationRequestRepository`的默认实现：`HttpSessionOAuth2AuthorizationRequestRepository`

**Requesting an Access Token - OAuth2AccessTokenResponseClient**

- `OAuth2AccessTokenResponseClient`的默认实现: `DefaultAuthorizationCodeTokenResponseClient`

用于向Authorization Server请求Access Token。默认实现`DefaultAuthorizationCodeTokenResponseClient`使用`RestOperations`向配置的Authorization Server Token Endpoint发送已有的authorization code来交换Access Token。

**自定义Access Token Request**

使用`DefaultAuthorizationCodeTokenResponseClient.setRequestEntityConverter()`来提供一个`Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>>`，可以在发送Access Token Request之前对请求做处理。

- 默认实现`OAuth2AuthorizationCodeGrantRequestEntityConverter`

**自定义Access Token Response**

使用`DefaultAuthorizationCodeTokenResponseClient.setRestOperations()`来提供一个自定义的`RestOperations`。默认的配置为：

```java
RestTemplate restTemplate = new RestTemplate(Arrays.asList(
        new FormHttpMessageConverter(),
        new OAuth2AccessTokenResponseHttpMessageConverter()));

restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
```

`OAuth2AccessTokenResponseHttpMessageConverter`是默认的Response Converter，可以使用`OAuth2AccessTokenResponseHttpMessageConverter.setTokenResponseConverter()`来提供一个`Converter<Map<String, String>, OAuth2AccessTokenResponse>`用来将Response的参数转换为`OAuth2AccessTokenResponse`。

配置：

```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .oauth2Client(oauth2 -> oauth2
                .authorizationCodeGrant(codeGrant -> codeGrant
                    .accessTokenResponseClient(this.accessTokenResponseClient())
                    ...
                )
            );
    }
}
```

#### Refresh Token

默认实现`DefaultRefreshTokenTokenResponseClient`使用`RestOperations`向配置的Authorization Server Token Endpoint请求新的Token。

**自定义Access Token Request**

使用`DefaultRefreshTokenTokenResponseClient.setRequestEntityConverter()`来提供一个`Converter<OAuth2RefreshTokenGrantRequest, RequestEntity<?>>`

- 默认实现: `OAuth2RefreshTokenGrantRequestEntityConverter`

**自定义Access Token Response**

使用`DefaultRefreshTokenTokenResponseClient.setRestOperations()`来提供`RestOperations`，默认实现:

```java
RestTemplate restTemplate = new RestTemplate(Arrays.asList(
        new FormHttpMessageConverter(),
        new OAuth2AccessTokenResponseHttpMessageConverter()));

restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
```

使用`OAuth2AccessTokenResponseHttpMessageConverter.setTokenResponseConverter()`来提供自定义的`Converter<Map<String, String>, OAuth2AccessTokenResponse>`

配置:

```java
// Customize
OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenTokenResponseClient = ...

OAuth2AuthorizedClientProvider authorizedClientProvider =
        OAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .refreshToken(configurer -> configurer.accessTokenResponseClient(refreshTokenTokenResponseClient))
                .build();

...

authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
```

在`authorization_code`或`password`模式下，`OAuth2RefreshToken`可能会随着Access Token Response一起返回。当`OAuth2AuthorizedClient.getRefreshToken()`可用，并且`OAuth2AuthorizedClient.getAccessToken()`过期时，会自动调用`RefreshTokenOAuth2AuthorizedClientProvider`来刷新Token。

#### Client Credentials

- 默认实现: `DefaultClientCredentialsTokenResponseClient`

**自定义Access Token Request**

调用`DefaultClientCredentialsTokenResponseClient.setRequestEntityConverter()`来提供一个`Converter<OAuth2ClientCredentialsGrantRequest, RequestEntity<?>>`

- 默认实现: `OAuth2ClientCredentialsGrantRequestEntityConverter`

**自定义Access Token Response**

调用`DefaultClientCredentialsTokenResponseClient.setRestOperations()`来提供`RestOperations`。默认实现:

```java
RestTemplate restTemplate = new RestTemplate(Arrays.asList(
        new FormHttpMessageConverter(),
        new OAuth2AccessTokenResponseHttpMessageConverter()));

restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
```

配置：

```java
// Customize
OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient = ...

OAuth2AuthorizedClientProvider authorizedClientProvider =
        OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials(configurer -> configurer.accessTokenResponseClient(clientCredentialsTokenResponseClient))
                .build();

...

authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
```

#### Resource Owner Password Credentials

- 默认实现: `DefaultPasswordTokenResponseClient`

**自定义Access Token Request**

`DefaultPasswordTokenResponseClient.setRequestEntityConverter()`提供`Converter<OAuth2PasswordGrantRequest, RequestEntity<?>>`

- 默认实现：`OAuth2PasswordGrantRequestEntityConverter`

**自定义Access Token Response**

`DefaultPasswordTokenResponseClient.setRestOperations()`，默认实现：

```java
RestTemplate restTemplate = new RestTemplate(Arrays.asList(
        new FormHttpMessageConverter(),
        new OAuth2AccessTokenResponseHttpMessageConverter()));

restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
```

`OAuth2AccessTokenResponseHttpMessageConverter.setTokenResponseConverter()`提供自定义`Converter<Map<String, String>, OAuth2AccessTokenResponse>`

配置：

```java
// Customize
OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> passwordTokenResponseClient = ...

OAuth2AuthorizedClientProvider authorizedClientProvider =
        OAuth2AuthorizedClientProviderBuilder.builder()
                .password(configurer -> configurer.accessTokenResponseClient(passwordTokenResponseClient))
                .refreshToken()
                .build();

...

authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
```

### Additional Features

`@RegisteredOAuth2AuthorizedClient`注解可用来装饰方法参数从而获取`OAuth2AuthorizedClient`。

```java
@Controller
public class OAuth2ClientController {

    @GetMapping("/")
    public String index(@RegisteredOAuth2AuthorizedClient("okta") OAuth2AuthorizedClient authorizedClient) {
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();

        ...

        return "index";
    }
}
```

- `@RegisteredOAuth2AuthorizedClient`是由`OAuth2AuthorizedClientArgumentResolver`来处理的，后者调用`OAuth2AuthorizedClientManager`来获取。

