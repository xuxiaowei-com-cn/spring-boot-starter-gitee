package org.springframework.security.oauth2.server.authorization.http;

/*-
 * #%L
 * spring-boot-starter-gitee
 * %%
 * Copyright (C) 2022 徐晓伟工作室
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.OAuth2GiteeParameterNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.GiteeService;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * 码云Gitee跳转到码云Gitee授权页面
 *
 * @see <a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
@Data
@EqualsAndHashCode(callSuper = true)
@Component
public class GiteeAuthorizeHttpFilter extends HttpFilter {

	public static final String PREFIX_URL = "/gitee/authorize";

	/**
	 * @see <a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 */
	public static final String AUTHORIZE_URL = "https://gitee.com/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s";

	/**
	 * 以snsapi_base为 scope 发起的网页授权，是用来获取进入页面的用户的 openid
	 * 的，并且是静默授权并自动跳转到回调页的。用户感知的就是直接进入了回调页（往往是业务页面）
	 * @see <a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 */
	public static final String USER_INFO = "user_info";

	public static final String PROJECTS = "projects";

	public static final String PULL_REQUESTS = "pull_requests";

	public static final String ISSUES = "issues";

	public static final String NOTES = "notes";

	public static final String KEYS = "keys";

	public static final String HOOK = "hook";

	public static final String GROUPS = "groups";

	public static final String GISTS = "gists";

	public static final String ENTERPRISES = "enterprises";

	private GiteeService giteeService;

	@Autowired
	public void setGiteeService(GiteeService giteeService) {
		this.giteeService = giteeService;
	}

	/**
	 * 码云Gitee授权前缀
	 */
	private String prefixUrl = PREFIX_URL;

	@Override
	protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String requestUri = request.getRequestURI();
		AntPathMatcher antPathMatcher = new AntPathMatcher();
		boolean match = antPathMatcher.match(prefixUrl + "/*", requestUri);
		if (match) {
			log.info("requestUri：{}", requestUri);

			String appid = requestUri.replace(prefixUrl + "/", "");

			String redirectUri = giteeService.getRedirectUriByAppid(appid);

			String binding = request.getParameter(OAuth2GiteeParameterNames.BINDING);
			String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
			List<String> scopeList = Splitter.on(" ").trimResults().splitToList(scope);
			List<String> legalList = Arrays.asList(USER_INFO, PROJECTS, PULL_REQUESTS, ISSUES, NOTES, KEYS, HOOK,
					GROUPS, GISTS, ENTERPRISES);
			Set<String> scopeResultSet = new HashSet<>();
			scopeResultSet.add(USER_INFO);
			for (String sc : scopeList) {
				if (legalList.contains(sc)) {
					scopeResultSet.add(sc);
				}
			}
			String scopeResult = Joiner.on(" ").join(scopeResultSet);

			String state = giteeService.stateGenerate(request, response, appid);
			giteeService.storeBinding(request, response, appid, state, binding);
			giteeService.storeUsers(request, response, appid, state, binding);

			String url = String.format(AUTHORIZE_URL, appid, redirectUri, scopeResult, state);

			log.info("redirectUrl：{}", url);

			response.sendRedirect(url);
			return;
		}

		super.doFilter(request, response, chain);
	}

}
