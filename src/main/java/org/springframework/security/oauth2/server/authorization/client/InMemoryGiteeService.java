package org.springframework.security.oauth2.server.authorization.client;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.GiteeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2GiteeParameterNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.exception.AppidGiteeException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectGiteeException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectUriGiteeException;
import org.springframework.security.oauth2.server.authorization.properties.GiteeProperties;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2GiteeEndpointUtils;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 码云Gitee 账户服务接口 基于内存的实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
public class InMemoryGiteeService implements GiteeService {

	private final GiteeProperties giteeProperties;

	public InMemoryGiteeService(GiteeProperties giteeProperties) {
		this.giteeProperties = giteeProperties;
	}

	/**
	 * 认证信息
	 * @param clientPrincipal 经过身份验证的客户端主体
	 * @param additionalParameters 附加参数
	 * @param details 登录信息
	 * @param appid AppID(码云Gitee client_id)
	 * @param code 授权码，<a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 * @param id
	 * @param credentials 证书
	 * @param login
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
	@Override
	public AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String code, Integer id,
			Object credentials, String login, String accessToken, String refreshToken, Integer expiresIn,
			String scope) {
		List<GrantedAuthority> authorities = new ArrayList<>();
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority(giteeProperties.getDefaultRole());
		authorities.add(authority);
		User user = new User(id + "", accessToken, authorities);

		UsernamePasswordAuthenticationToken principal = UsernamePasswordAuthenticationToken.authenticated(user, null,
				user.getAuthorities());

		GiteeAuthenticationToken authenticationToken = new GiteeAuthenticationToken(authorities, clientPrincipal,
				principal, user, additionalParameters, details, appid, code, id);

		authenticationToken.setCredentials(credentials);
		authenticationToken.setLogin(login);

		return authenticationToken;
	}

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
	@Override
	public GiteeTokenResponse getAccessTokenResponse(String appid, String code, String accessTokenUrl) {
		Map<String, String> uriVariables = new HashMap<>(8);
		uriVariables.put(OAuth2ParameterNames.CLIENT_ID, appid);

		GiteeProperties.Gitee gitee = getGiteeByAppid(appid);
		String secret = gitee.getSecret();
		String redirectUriPrefix = gitee.getRedirectUriPrefix();
		String redirectUri = redirectUriPrefix + "/" + appid;

		uriVariables.put(OAuth2ParameterNames.CLIENT_SECRET, secret);
		uriVariables.put(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
		uriVariables.put(OAuth2GiteeParameterNames.CODE, code);

		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setContentType(MediaType.APPLICATION_JSON);
		HttpEntity<?> httpEntity = new HttpEntity<>(httpHeaders);

		GiteeTokenResponse giteeTokenResponse;
		try {
			giteeTokenResponse = restTemplate.postForObject(accessTokenUrl, httpEntity, GiteeTokenResponse.class,
					uriVariables);
		}
		catch (Exception e) {
			OAuth2Error error = new OAuth2Error(OAuth2GiteeEndpointUtils.ERROR_CODE,
					"使用码云Gitee授权code：" + code + " 获取Token异常", OAuth2GiteeEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error, e);
		}

		if (giteeTokenResponse == null) {
			OAuth2Error error = new OAuth2Error(OAuth2GiteeEndpointUtils.ERROR_CODE,
					"使用码云Gitee授权code：" + code + " 获取Token异常", OAuth2GiteeEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error);
		}

		String accessToken = giteeTokenResponse.getAccessToken();
		if (accessToken == null) {
			OAuth2Error error = new OAuth2Error(giteeTokenResponse.getError(), giteeTokenResponse.getErrorDescription(),
					OAuth2GiteeEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error);
		}

		return giteeTokenResponse;
	}

	/**
	 * 获取授权用户的资料
	 * @param userinfoUrl 用户信息接口
	 * @param appid AppID(码云Gitee client_id)
	 * @param giteeTokenResponse 码云 Token
	 * @see <a href="https://gitee.com/api/v5/swagger#/getV5User">获取授权用户的资料</a>
	 * @return 返回授权用户的资料
	 */
	@Override
	public GiteeUserInfoResponse getUserInfo(String userinfoUrl, String appid,
			@NonNull GiteeTokenResponse giteeTokenResponse) {

		String accessToken = giteeTokenResponse.getAccessToken();

		RestTemplate restTemplate = new RestTemplate();

		GiteeUserInfoResponse giteeUserInfoResponse;
		try {
			giteeUserInfoResponse = restTemplate.getForObject(userinfoUrl + "?access_token=" + accessToken,
					GiteeUserInfoResponse.class);
		}
		catch (Exception e) {
			OAuth2Error error = new OAuth2Error(OAuth2GiteeEndpointUtils.ERROR_CODE,
					"使用Token：" + accessToken + " 获取用户信息异常", OAuth2GiteeEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error, e);
		}

		if (giteeUserInfoResponse == null) {
			OAuth2Error error = new OAuth2Error(OAuth2GiteeEndpointUtils.ERROR_CODE,
					"使用Token：" + accessToken + " 获取用户信息异常", OAuth2GiteeEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error);
		}

		Integer id = giteeUserInfoResponse.getId();
		if (id == null) {
			OAuth2Error error = new OAuth2Error(OAuth2GiteeEndpointUtils.ERROR_CODE, giteeUserInfoResponse.getMessage(),
					OAuth2GiteeEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error);
		}

		try {
			GiteeUserInfoResponse response = restTemplate.getForObject(giteeUserInfoResponse.getUrl(),
					GiteeUserInfoResponse.class);
			if (response != null) {
				giteeUserInfoResponse.setCompany(response.getCompany());
				giteeUserInfoResponse.setProfession(response.getProfession());
				giteeUserInfoResponse.setWechat(response.getWechat());
				giteeUserInfoResponse.setQq(response.getQq());
				giteeUserInfoResponse.setLinkedin(response.getLinkedin());
			}
		}
		catch (Exception e) {
			log.error("获取码云Gitee用户公开信息异常", e);
		}

		return giteeUserInfoResponse;
	}

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
	@Override
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, Map<String, String> uriVariables,
			OAuth2AccessTokenResponse oauth2AccessTokenResponse, GiteeProperties.Gitee gitee) {

		OAuth2AccessToken accessToken = oauth2AccessTokenResponse.getAccessToken();

		try {
			response.sendRedirect(
					gitee.getSuccessUrl() + "?" + gitee.getParameterName() + "=" + accessToken.getTokenValue());
		}
		catch (IOException e) {
			OAuth2Error error = new OAuth2Error(OAuth2GiteeEndpointUtils.ERROR_CODE, "码云Gitee重定向异常", null);
			throw new RedirectGiteeException(error, e);
		}
	}

	/**
	 * 根据 appid 获取 码云Gitee属性配置
	 * @param appid 码云Gitee client_id
	 * @return 返回 码云Gitee属性配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public GiteeProperties.Gitee getGiteeByAppid(String appid) {
		List<GiteeProperties.Gitee> list = giteeProperties.getList();
		if (list == null) {
			OAuth2Error error = new OAuth2Error(OAuth2GiteeEndpointUtils.ERROR_CODE, "appid 未配置", null);
			throw new AppidGiteeException(error);
		}

		for (GiteeProperties.Gitee gitee : list) {
			if (appid.equals(gitee.getAppid())) {
				return gitee;
			}
		}
		OAuth2Error error = new OAuth2Error(OAuth2GiteeEndpointUtils.ERROR_CODE, "未匹配到 appid", null);
		throw new AppidGiteeException(error);
	}

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
	@Override
	public OAuth2AccessTokenResponse getOAuth2AccessTokenResponse(HttpServletRequest request,
			HttpServletResponse response, String tokenUrlPrefix, String tokenUrl, Map<String, String> uriVariables)
			throws OAuth2AuthenticationException {

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setContentType(MediaType.APPLICATION_JSON);
		HttpEntity<?> httpEntity = new HttpEntity<>(httpHeaders);

		RestTemplate restTemplate = new RestTemplate();

		List<HttpMessageConverter<?>> messageConverters = restTemplate.getMessageConverters();
		messageConverters.add(5, new OAuth2AccessTokenResponseHttpMessageConverter());

		return restTemplate.postForObject(tokenUrlPrefix + tokenUrl, httpEntity, OAuth2AccessTokenResponse.class,
				uriVariables);
	}

	/**
	 * 根据 appid 获取重定向的地址
	 * @param appid 码云Gitee client_id
	 * @return 返回重定向的地址
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public String getRedirectUriByAppid(String appid) throws OAuth2AuthenticationException {
		GiteeProperties.Gitee gitee = getGiteeByAppid(appid);
		String redirectUriPrefix = gitee.getRedirectUriPrefix();

		if (StringUtils.hasText(redirectUriPrefix)) {
			return UriUtils.encode(redirectUriPrefix + "/" + appid, StandardCharsets.UTF_8);
		}
		else {
			OAuth2Error error = new OAuth2Error(OAuth2GiteeEndpointUtils.ERROR_CODE, "重定向地址前缀不能为空", null);
			throw new RedirectUriGiteeException(error);
		}
	}

}
