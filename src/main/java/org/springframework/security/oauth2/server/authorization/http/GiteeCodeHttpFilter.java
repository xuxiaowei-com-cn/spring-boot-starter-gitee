package org.springframework.security.oauth2.server.authorization.http;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.*;
import org.springframework.security.oauth2.server.authorization.client.GiteeService;
import org.springframework.security.oauth2.server.authorization.properties.GiteeProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2GiteeAuthenticationToken.GITEE;

/**
 * 码云Gitee授权码接收服务
 *
 * @see <a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2AccessTokenResponse
 * @see DefaultOAuth2AccessTokenResponseMapConverter
 * @see DefaultMapOAuth2AccessTokenResponseConverter
 */
@Slf4j
@Data
@EqualsAndHashCode(callSuper = true)
@Component
public class GiteeCodeHttpFilter extends HttpFilter {

	public static final String PREFIX_URL = "/gitee/code";

	public static final String TOKEN_URL = "/oauth2/token?grant_type={grant_type}&appid={appid}&code={code}&state={state}&client_id={client_id}&client_secret={client_secret}&remote_address={remote_address}&session_id={session_id}";

	/**
	 * 码云Gitee使用code获取授权凭证URL前缀
	 */
	private String prefixUrl = PREFIX_URL;

	private GiteeProperties giteeProperties;

	private GiteeService giteeService;

	@Autowired
	public void setGiteeProperties(GiteeProperties giteeProperties) {
		this.giteeProperties = giteeProperties;
	}

	@Autowired
	public void setGiteeService(GiteeService giteeService) {
		this.giteeService = giteeService;
	}

	@Override
	protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String requestUri = request.getRequestURI();
		AntPathMatcher antPathMatcher = new AntPathMatcher();
		boolean match = antPathMatcher.match(prefixUrl + "/*", requestUri);
		if (match) {
			log.info("requestUri：{}", requestUri);

			String appid = requestUri.replace(prefixUrl + "/", "");
			String code = request.getParameter(OAuth2ParameterNames.CODE);
			String state = request.getParameter(OAuth2ParameterNames.STATE);
			String grantType = GITEE.getValue();

			GiteeProperties.Gitee gitee = giteeService.getGiteeByAppid(appid);
			String clientId = gitee.getClientId();
			String clientSecret = gitee.getClientSecret();
			String tokenUrlPrefix = gitee.getTokenUrlPrefix();
			String scope = gitee.getScope();

			String remoteHost = request.getRemoteHost();
			HttpSession session = request.getSession(false);

			Map<String, String> uriVariables = new HashMap<>(8);
			uriVariables.put(OAuth2ParameterNames.GRANT_TYPE, grantType);
			uriVariables.put(OAuth2GiteeParameterNames.APPID, appid);
			uriVariables.put(OAuth2ParameterNames.CODE, code);
			uriVariables.put(OAuth2ParameterNames.STATE, state);
			uriVariables.put(OAuth2ParameterNames.SCOPE, scope);
			uriVariables.put(OAuth2ParameterNames.CLIENT_ID, clientId);
			uriVariables.put(OAuth2ParameterNames.CLIENT_SECRET, clientSecret);
			uriVariables.put(OAuth2GiteeParameterNames.REMOTE_ADDRESS, remoteHost);
			uriVariables.put(OAuth2GiteeParameterNames.SESSION_ID, session == null ? "" : session.getId());

			OAuth2AccessTokenResponse oauth2AccessTokenResponse = giteeService.getOAuth2AccessTokenResponse(request,
					response, tokenUrlPrefix, TOKEN_URL, uriVariables);
			if (oauth2AccessTokenResponse == null) {
				return;
			}

			giteeService.sendRedirect(request, response, uriVariables, oauth2AccessTokenResponse, gitee);
			return;
		}

		super.doFilter(request, response, chain);
	}

}