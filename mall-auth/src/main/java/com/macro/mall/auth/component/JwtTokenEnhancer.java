package com.macro.mall.auth.component;

import com.macro.mall.auth.domain.SecurityUser;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * JWT内容增强器
 * 用来给TOKEN加入一些额外信息
 * Created by macro on 2020/6/19.
 */
@Component
public class JwtTokenEnhancer implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        /**
         * 在AuthorizationServerConfigurerAdapter.configure(AuthorizationServerEndpointsConfigurer endpoints)中
         * 会配置userDetailsService。这个service用来配置实现通过用户名获取用户信息的方法。
         * 这里的authentication.getPrincipal()返回的是userDetails,而其对应的实现方法是从配置的userDetailsService中获取的
         * 所以这里强转成SecurityUser
         */
        SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();
        Map<String, Object> info = new HashMap<>();
        //把用户ID设置到JWT中
        info.put("id", securityUser.getId());
        info.put("client_id",securityUser.getClientId());
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(info);
        return accessToken;
    }
}
