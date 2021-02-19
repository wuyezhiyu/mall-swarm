package com.macro.mall.auth.config;

import com.macro.mall.auth.component.JwtTokenEnhancer;
import com.macro.mall.auth.service.impl.UserServiceImpl;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.rsa.crypto.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

/**
 * 认证服务器配置
 * Created by macro on 2020/6/19.
 */
@AllArgsConstructor
@Configuration
@EnableAuthorizationServer
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final UserServiceImpl userDetailsService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenEnhancer jwtTokenEnhancer;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("admin-app")
                .secret(passwordEncoder.encode("123456"))
                .scopes("all")
                .authorizedGrantTypes("password", "refresh_token")
                .accessTokenValiditySeconds(3600*24)
                .refreshTokenValiditySeconds(3600*24*7)
                .and()
                .withClient("portal-app")
                .secret(passwordEncoder.encode("123456"))
                .scopes("all")
                .authorizedGrantTypes("password", "refresh_token")
                .accessTokenValiditySeconds(3600*24)
                .refreshTokenValiditySeconds(3600*24*7);
    }

    /**
     * 对授权服务端点（Authorization Server endpoints）进行一些配置，主要包括 增强器，以及一些与授权功能相关的属性
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
        List<TokenEnhancer> delegates = new ArrayList<>();
        delegates.add(jwtTokenEnhancer);
        delegates.add(accessTokenConverter());
        enhancerChain.setTokenEnhancers(delegates); //配置JWT的内容增强器
        endpoints.authenticationManager(authenticationManager)
                /**
                 * userDetailsService 是一个接口，并且只包含了一个方法，通过用户名获取用户信息（UserDetails）
                 * 作用是帮助增强器获取用户信息？？？
                 */
                .userDetailsService(userDetailsService)
                .accessTokenConverter(accessTokenConverter())
                .tokenEnhancer(enhancerChain);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                //在调用/oauth/token获取token时，可以通过表单方式传递client_id 和 client_secret。
                //如果不配置，则调用/oauth/token时需要通过Basic Auth的方式传递
                .allowFormAuthenticationForClients();
    }

    /**
     * JwtAccessTokenConverter
     * Helper that translates between JWT encoded token values and OAuth authentication  information (in both directions).
     * Also acts as a TokenEnhancer when tokens are  granted.
     * JwtAccessTokenConverter做两件事情。
     * 1，将JWT字符串 与 JWT系统解密对象（识别JWT） 之间进行转换。因为这里需要用到私钥，所以配置了KeyPair
     * 2.当Token生成的时候，JwtAccessTokenConverter 还会作为TOKEN增强器被加入 token增强器链中
     */
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setKeyPair(keyPair());
        return jwtAccessTokenConverter;
    }

    @Bean
    public KeyPair keyPair() {
        //从classpath下的证书中获取秘钥对
        /**
         * 这里有两个 "123456".toCharArray()  ，它们虽然都是密码，但是作用不一样
         *
         * KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "123456".toCharArray());
         * 第一个密码是keystore密码库的密码
         *
         * keyStoreKeyFactory.getKeyPair("jwt", "123456".toCharArray());
         * 第二个密码是可用来获取 私钥
         *
         */
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "123456".toCharArray());
        return keyStoreKeyFactory.getKeyPair("jwt", "123456".toCharArray());

        /**
         * 下面这段代码，可通过keytool生成的文件，演示  公钥加密，私钥解密 的过程。
         * 上面两句代码背后的具体实现也可参考如下代码（配合参数 oauth2.0bookmark\电商平台脚手架相关\Keytool命令详解 了解keytool的使用）
         *
         * // 公钥加密，私钥解密示例程序
         * public class A {
         *  public static void main(String[] args) throws Exception {
         *
         *   // 前提：JDK已安装且正确配置环境变量
         *   // 首先在C盘建立目录 MyKeyStore，用来存放证书库以及导出的证书文件，然后在命令行执行下列2句
         *   // 下句含义：在当前目录创建 TestStore 密钥库，库密码 aaaaaa ，创建证书 TestKey2 ：非对称密钥，RSA 算法，key密码为 bbbbbb ，存于 TestStore
         *   // C:/MyKeyStore > keytool -genkey -alias TestKey2 -dname "CN=test222" -keyalg RSA -keystore TestStore -storepass aaaaaa -keypass bbbbbb
         *   // 下句含义：将 TestStore 库中的 TestKey2 导出为证书文件 TestKey2.cer ，这里可能需要将 export 修改为 exportcert
         *   // C:/MyKeyStore > keytool -export -alias TestKey2 -file TestKey2.cer -keystore TestStore -storepass aaaaaa
         *   // 证书库证书保存证书的公私钥，导出的证书文件只携带公钥
         *
         *
         *
         *   byte[] msg = "犯大汉天威者，虽远必诛！".getBytes("UTF8");     // 待加解密的消息
         *
         *   // 用证书的公钥加密
         *   CertificateFactory cff = CertificateFactory.getInstance("X.509");
         *   FileInputStream fis1 = new FileInputStream("C://MyKeyStore//TestKey2.cer"); // 证书文件
         *   Certificate cf = cff.generateCertificate(fis1);
         *   PublicKey pk1 = cf.getPublicKey();           // 得到证书文件携带的公钥
         *   Cipher c1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");      // 定义算法：RSA
         *   c1.init(Cipher.ENCRYPT_MODE, pk1);
         *   byte[] msg1 = c1.doFinal(msg);            // 加密后的数据
         *
         *   // 用证书的私钥解密 - 该私钥存在生成该证书的密钥库中
         *   FileInputStream fis2 = new FileInputStream("C://MyKeyStore//TestStore");
         *   KeyStore ks = KeyStore.getInstance("JKS");         // 加载证书库
         *   char[] kspwd = "aaaaaa".toCharArray();          // 证书库密码
         *   char[] keypwd = "bbbbbb".toCharArray();          // 证书密码
         *   ks.load(fis2, kspwd);              // 加载证书
         *   PrivateKey pk2 = (PrivateKey)ks.getKey("TestKey2", keypwd);     // 获取证书私钥
         *   fis2.close();
         *   Cipher c2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
         *   c2.init(Cipher.DECRYPT_MODE, pk2);
         *   byte[] msg2 = c2.doFinal(msg1);            // 解密后的数据
         *
         *   // 打印解密字符串 - 应显示 犯大汉天威者，虽远必诛！
         *   System.out.println(new String(msg2,"UTF8"));        // 将解密数据转为字符串
         *  }
         * }
         */
    }

}
