package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

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

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.GiteeService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryGiteeService;
import org.springframework.security.oauth2.server.authorization.properties.GiteeProperties;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * 码云Gitee OAuth 2.0 配置器的实用方法。
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2ConfigurerUtils
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2GiteeConfigurerUtils {

	public static OAuth2AuthorizationService getAuthorizationService(HttpSecurity httpSecurity) {
		return OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity);
	}

	public static OAuth2TokenGenerator<? extends OAuth2Token> getTokenGenerator(HttpSecurity httpSecurity) {
		return OAuth2ConfigurerUtils.getTokenGenerator(httpSecurity);
	}

	public static GiteeService getGiteeService(HttpSecurity httpSecurity) {
		GiteeService giteeService = httpSecurity.getSharedObject(GiteeService.class);
		if (giteeService == null) {
			giteeService = OAuth2ConfigurerUtils.getOptionalBean(httpSecurity, GiteeService.class);
			if (giteeService == null) {
				GiteeProperties giteeProperties = OAuth2ConfigurerUtils.getOptionalBean(httpSecurity,
						GiteeProperties.class);
				giteeService = new InMemoryGiteeService(giteeProperties);
			}
		}
		return giteeService;
	}

}
