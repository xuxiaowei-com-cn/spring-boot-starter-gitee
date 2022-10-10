package org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.client.GiteeService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryGiteeService;
import org.springframework.security.oauth2.server.authorization.properties.GiteeProperties;

/**
 * 码云Gitee 配置
 *
 * @author xuxiaowei
 * @see OAuth2AuthorizationServerConfiguration
 * @since 0.0.1
 */
@Configuration
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2GiteeConfiguration {

	private GiteeProperties giteeProperties;

	@Autowired
	public void setGiteeProperties(GiteeProperties giteeProperties) {
		this.giteeProperties = giteeProperties;
	}

	@Bean
	@ConditionalOnMissingBean
	public GiteeService giteeService() {
		return new InMemoryGiteeService(giteeProperties);
	}

}
