package org.springframework.security.oauth2.server.authorization.client;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.properties.GiteeProperties;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.util.Map;

/**
 * 码云Gitee 账户服务接口
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see RegisteredClientRepository
 * @see InMemoryRegisteredClientRepository
 * @see JdbcRegisteredClientRepository
 */
public interface GiteeService {

	/**
	 * 认证信息
	 * @param clientPrincipal 经过身份验证的客户端主体
	 * @param additionalParameters 附加参数
	 * @param details 登录信息
	 * @param appid AppID(码云Gitee client_id)
	 * @param code 授权码，<a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 * @param id 用户唯一标识，<a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 * @param credentials 证书
	 * @param login 多账户用户唯一标识，<a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 * @param accessToken 授权凭证，<a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 * @param refreshToken 刷新凭证，<a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 * @param expiresIn 过期时间，<a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 * @param scope {@link OAuth2ParameterNames#SCOPE}，授权范围，<a href=
	 * "https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 * @return 返回 认证信息
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String code, Integer id,
			Object credentials, String login, String accessToken, String refreshToken, Integer expiresIn, String scope)
			throws OAuth2AuthenticationException;

	/**
	 * 根据 AppID(码云Gitee client_id)、code、jsCode2SessionUrl 获取Token
	 * @param appid AppID(码云Gitee
	 * client_id)，<a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 * @param code 授权码，<a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 * @param accessTokenUrl <a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 * @return 返回 码云Gitee授权结果
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	GiteeTokenResponse getAccessTokenResponse(String appid, String code, String accessTokenUrl)
			throws OAuth2AuthenticationException;

	/**
	 * 获取授权用户的资料
	 * @param userinfoUrl 用户信息接口
	 * @param accessToken 授权Token
	 * @see <a href="https://gitee.com/api/v5/swagger#/getV5User">获取授权用户的资料</a>
	 * @return 返回授权用户的资料
	 */
	GiteeUserInfoResponse getUserInfo(String userinfoUrl, String accessToken);

	/**
	 * 授权成功重定向方法
	 * @param request 请求
	 * @param response 响应
	 * @param uriVariables 参数
	 * @param oauth2AccessTokenResponse OAuth2.1 授权 Token
	 * @param gitee 码云Gitee配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	void sendRedirect(HttpServletRequest request, HttpServletResponse response, Map<String, String> uriVariables,
			OAuth2AccessTokenResponse oauth2AccessTokenResponse, GiteeProperties.Gitee gitee)
			throws OAuth2AuthenticationException;

	/**
	 * 根据 appid 获取 码云Gitee属性配置
	 * @param appid 码云Gitee client_id
	 * @return 返回 码云Gitee属性配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	GiteeProperties.Gitee getGiteeByAppid(String appid) throws OAuth2AuthenticationException;

	/**
	 * 获取 OAuth 2.1 授权 Token（如果不想执行此方法后面的内容，可返回 null）
	 * @param request 请求
	 * @param response 响应
	 * @param tokenUrlPrefix 获取 Token URL 前缀
	 * @param tokenUrl Token URL
	 * @param uriVariables 参数
	 * @return 返回 OAuth 2.1 授权 Token
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	OAuth2AccessTokenResponse getOAuth2AccessTokenResponse(HttpServletRequest request, HttpServletResponse response,
			String tokenUrlPrefix, String tokenUrl, Map<String, String> uriVariables)
			throws OAuth2AuthenticationException;

	/**
	 * 根据 appid 获取重定向的地址
	 * @param appid 码云Gitee client_id
	 * @return 返回重定向的地址
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	String getRedirectUriByAppid(String appid);

}
