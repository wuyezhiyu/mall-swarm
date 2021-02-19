package com.macro.mall.config;

import cn.hutool.core.util.ArrayUtil;
import com.macro.mall.authorization.AuthorizationManager;
import com.macro.mall.common.constant.AuthConstant;
import com.macro.mall.component.RestAuthenticationEntryPoint;
import com.macro.mall.component.RestfulAccessDeniedHandler;
import com.macro.mall.filter.IgnoreUrlsRemoveJwtFilter;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

/**
 * 资源服务器配置
 * Created by macro on 2020/6/19.
 */
@AllArgsConstructor
@Configuration
@EnableWebFluxSecurity
public class ResourceServerConfig {
    private final AuthorizationManager authorizationManager;
    private final IgnoreUrlsConfig ignoreUrlsConfig;
    private final RestfulAccessDeniedHandler restfulAccessDeniedHandler;
    private final RestAuthenticationEntryPoint restAuthenticationEntryPoint;
    private final IgnoreUrlsRemoveJwtFilter ignoreUrlsRemoveJwtFilter;

    /**
     *
     * ServerHttpSecurity
     * A  ServerHttpSecurity  is similar to Spring Security's HttpSecurity but for WebFlux.
     * It allows configuring web based security for specific http requests. By default it will be applied to all requests,
     * but can be restricted using   securityMatcher(ServerWebExchangeMatcher) or other similar methods.
     *
     * 与HttpSecurity类似，ServerHttpSecurity可以为http请求配置一些安全相关的配置，但是是包含WebFlux特性的。
     * 默认情况下，配置是针对所有请求的，可以通过类似securityMatcher的方法对配置的请求进行过滤。
     *
     *
     * @param http 通过它，可以为全局的http请求配置一些安全配置
     * @return
     */
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        //采用oauth2登录方式？？ 并定义Jwt相关配置
        http
                //Configures OAuth 2.0 Resource Server support.
                .oauth2ResourceServer()
                //Enables JWT Resource Server support.
                .jwt()
                //Configures the Converter to use for converting a Jwt into an AbstractAuthenticationToken.
                .jwtAuthenticationConverter(jwtAuthenticationConverter());
        //自定义处理JWT请求头过期或签名错误的结果（访问请求没有经过身份验证时进入）
        //AuthorizationManager.check 返回 new AuthorizationDecision(false)时会进入这里？？？
        /**
         * 它在用户请求处理过程中遇到认证异常时，被ExceptionTranslationFilter用于开启特定认证方案(authentication schema)的认证流程。
         * 该接口只定义了一个方法，该commence实现相应的认证方案逻辑，这会修改response并返回给用户，引导用户进入认证流程。
         * https://blog.csdn.net/andy_zhang2007/article/details/91355520
         */
        http.oauth2ResourceServer().authenticationEntryPoint(restAuthenticationEntryPoint);
        //对白名单路径，直接移除JWT请求头
        //该过滤器被配置在 其他过滤器的前端，具体在filter调用链中的执行顺序由第二个参数 SecurityWebFiltersOrder.AUTHENTICATION 指定
        http.addFilterBefore(ignoreUrlsRemoveJwtFilter,SecurityWebFiltersOrder.AUTHENTICATION);

        //通过流式编程配置鉴权逻辑 具体看注释   AuthorizeExchangeSpec是用来对http请求配置鉴权规则的荷载
        http.authorizeExchange()
                /**
                 * pathMatchers 为AuthorizeExchangeSpec对象分配接收到的match，并返回new Access()  (已与该为AuthorizeExchangeSpec 关联)
                 *
                 * permitAll 返回new AuthorizationDecision(true) 。  return access( (a, e) -> Mono.just(new AuthorizationDecision(true)));
                 * 插入一个自定义授权策略（之前match选中的请求都允许通过）
                 * 最后返回原来的AuthorizeExchangeSpec对象
                 *
                 *
                 * pathMatchers 是 AuthorizeExchangeSpec对象调用的，并且会返回一个new Access对象
                 * Access.permitAll会返回创建这个Access的AuthorizeExchangeSpec对象（由于Access类定义在AuthorizeExchangeSpec类内部，所以可以
                 * 在Access的方法中通过AuthorizeExchangeSpec.this的方式调用在其域中创建这个Access的AuthorizeExchangeSpec对象），从而实现流式编程
                 */
                .pathMatchers(ArrayUtil.toArray(ignoreUrlsConfig.getUrls(),String.class)).permitAll()//白名单配置

                /**
                 * anyExchange 根据上面的配置，对选中的request进行map操作。即如果访问路径如果满足白名单，则授权通过，
                 * 实际上是做了一些配置 例如 this.anyExchangeRegistered = true  this.matcher = matcher; （this就是AuthorizeExchangeSpec）
                 *
                 * access  允许插入自定义授权策略   Allows plugging in a custom authorization strategy
                 * 如果当前请求已经被标记为通过判定，则如下函数会如何判断？？
                 */
                .anyExchange().access(authorizationManager)

                /**
                 * and ：Allows method chaining to continue configuring the {@link ServerHttpSecurity}
                 * 返回 ServerHttpSecurity 对象，允许继续配置
                 *
                 * 添加异常处理器
                 */
                .and().exceptionHandling()
                .accessDeniedHandler(restfulAccessDeniedHandler)//处理未授权。鉴权未通过的请求处理
                .authenticationEntryPoint(restAuthenticationEntryPoint)//处理未认证。处理一个没有经过认证（没有token或token是假的？？）的请求

                .and().csrf().disable();//禁用CSRF保护

        //build方法 构造的filter调用链，及配置信息等   返回一个 SecurityWebFilterChain（构造一个过滤器链，用来鉴别该request是否可以通过）
        return http.build();
    }

    @Bean
    public Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter() {
        //从众多jwt中的属性中，提取出 权限内容
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        //AUTHORITY_PREFIX JWT存储权限前缀
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix(AuthConstant.AUTHORITY_PREFIX);
        // AUTHORITY_CLAIM_NAME JWT存储权限属性
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName(AuthConstant.AUTHORITY_CLAIM_NAME);
        //将 Jwt 对象转换成 AbstractAuthenticationToken 对象
        // JwtAuthenticationToken extends AbstractOAuth2TokenAuthenticationToken<Jwt>
        //AbstractOAuth2TokenAuthenticationToken<T extends AbstractOAuth2Token> extends AbstractAuthenticationToken
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        //转换器  将Jwt 转换成 Mono<AbstractAuthenticationToken>   Mono是一个泛型
        return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
    }

}
