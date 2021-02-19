package com.macro.mall.authorization;

import cn.hutool.core.convert.Convert;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONUtil;
import com.macro.mall.common.constant.AuthConstant;
import com.macro.mall.common.domain.UserDto;
import com.macro.mall.config.IgnoreUrlsConfig;
import com.nimbusds.jose.JWSObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 鉴权管理器，用于判断是否有资源的访问权限
 * Created by macro on 2020/6/19.
 */
@Component
public class AuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    @Autowired
    private IgnoreUrlsConfig ignoreUrlsConfig;

    /**
     * Determines if access is granted for a specific authentication and object
     * 确定是否为特定的身份验证和对象授予访问权限
     * @param mono the Authentication to check 需要被检查的身份验证信息
     * @param authorizationContext the object to check 需要被检查的对象
     * @return
     */
    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> mono, AuthorizationContext authorizationContext) {
        //new AuthorizationDecision(true) 标识通过   new AuthorizationDecision(false) 标识拒绝
        //authorizationContext 包含了当前用户请求的上下文
        ServerHttpRequest request = authorizationContext.getExchange().getRequest();
        URI uri = request.getURI();
        PathMatcher pathMatcher = new AntPathMatcher();
        //白名单路径直接放行
        List<String> ignoreUrls = ignoreUrlsConfig.getUrls();
        for (String ignoreUrl : ignoreUrls) {
            if (pathMatcher.match(ignoreUrl, uri.getPath())) {
                return Mono.just(new AuthorizationDecision(true));
            }
        }
        //对应跨域的预检请求直接放行
        if(request.getMethod()==HttpMethod.OPTIONS){
            return Mono.just(new AuthorizationDecision(true));
        }
        //不同用户体系登录不允许互相访问
        try {
            String token = request.getHeaders().getFirst(AuthConstant.JWT_TOKEN_HEADER);
            if(StrUtil.isEmpty(token)){
                return Mono.just(new AuthorizationDecision(false));
            }
            String realToken = token.replace(AuthConstant.JWT_TOKEN_PREFIX, "");
            JWSObject jwsObject = JWSObject.parse(realToken);
            String userStr = jwsObject.getPayload().toString();
            UserDto userDto = JSONUtil.toBean(userStr, UserDto.class);
            //client和uri的路径的前缀对不上
            if (AuthConstant.ADMIN_CLIENT_ID.equals(userDto.getClientId()) && !pathMatcher.match(AuthConstant.ADMIN_URL_PATTERN, uri.getPath())) {
                return Mono.just(new AuthorizationDecision(false));
            }
            if (AuthConstant.PORTAL_CLIENT_ID.equals(userDto.getClientId()) && pathMatcher.match(AuthConstant.ADMIN_URL_PATTERN, uri.getPath())) {
                return Mono.just(new AuthorizationDecision(false));
            }
        } catch (ParseException e) {
            e.printStackTrace();
            return Mono.just(new AuthorizationDecision(false));
        }
        //非管理端路径直接放行
        if (!pathMatcher.match(AuthConstant.ADMIN_URL_PATTERN, uri.getPath())) {
            return Mono.just(new AuthorizationDecision(true));
        }
        //管理端路径需校验权限  （可优化!!!）

        Map<Object, Object> resourceRolesMap = redisTemplate.opsForHash().entries(AuthConstant.RESOURCE_ROLES_MAP_KEY);
        Iterator<Object> iterator = resourceRolesMap.keySet().iterator();
        //获取包含当前URI的所有角色？？？
        List<String> authorities = new ArrayList<>();
        while (iterator.hasNext()) {
            String pattern = (String) iterator.next();
            if (pathMatcher.match(pattern, uri.getPath())) {
                authorities.addAll(Convert.toList(String.class, resourceRolesMap.get(pattern)));
            }
        }
        authorities = authorities.stream().map(i -> i = AuthConstant.AUTHORITY_PREFIX + i).collect(Collectors.toList());
        //该mono擦用响应式编程模型，包含一个 封装了权限验证信息的对象
        return mono
                //是否已经经过了身份验证（非权限验证，权限验证时动态的）
                //遍历 mono中的元素（只有一个），如果 Predicate对象返回true则保留这个元素
                .filter(Authentication::isAuthenticated)
                //遍历 mono中的元素（只有一个），将每个元素（通过return）转换成Iterable对象
                //生成的Flux对象包含的不是 一个[1，2]序列 而是单独的 1,2
                //如果mono换成Flux，flatMapIterable会将多个元素的转换结果合并成一个序列。例如 1-> 1,2  和 3-> 3,4会合并成1，2，3，4  而不是 [1,2],[3,4]
                //这里会剥离授予当前用户（principal）的权限信息（getAuthorities，还是封装在Authentication中）。可能是个空对象，不会时null
                .flatMapIterable(Authentication::getAuthorities)
                //将权限信息转换成字符串
                .map(GrantedAuthority::getAuthority)
                //遍历Flux中的对象，如果任何一个满足Predicate对象则返回true，否则返回false,并封装金.authorities是能够访问当前url的所有权限，这里将会检查当前用户所持有的权限是否包含其中
                .any(authorities::contains)
                //将true或false转换成 new AuthorizationDecision(true)或 new AuthorizationDecision(false)
                .map(AuthorizationDecision::new)
                //如果mono为空，则给他装入一个固定的对象
                .defaultIfEmpty(new AuthorizationDecision(false));
    }
}
