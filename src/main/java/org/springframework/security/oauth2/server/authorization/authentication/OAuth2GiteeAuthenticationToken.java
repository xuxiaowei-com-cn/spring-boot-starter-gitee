package org.springframework.security.oauth2.server.authorization.authentication;

import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;

import java.util.Map;

/**
 * 码云Gitee OAuth2 身份验证令牌
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2AuthorizationCodeAuthenticationToken 用于 OAuth 2.0 授权代码授予的
 * {@link Authentication} 实现。
 * @see OAuth2RefreshTokenAuthenticationToken 用于 OAuth 2.0 刷新令牌授予的 {@link Authentication}
 * 实现。
 * @see OAuth2ClientCredentialsAuthenticationToken 用于 OAuth 2.0
 * 客户端凭据授予的{@link Authentication} 实现。
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2GiteeAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	/**
	 * 授权类型：码云Gitee
	 */
	public static final AuthorizationGrantType GITEE = new AuthorizationGrantType("gitee");

	/**
	 * AppID(码云Gitee client_id)
	 */
	@Getter
	private final String appid;

	/**
	 * @see <a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 */
	@Getter
	private final String code;

	/**
	 * @see OAuth2ParameterNames#SCOPE
	 */
	@Getter
	private final String scope;

	@Getter
	private final String remoteAddress;

	@Getter
	private final String sessionId;

	@Getter
	private final String state;

	@Getter
	private final String binding;

	/**
	 * 子类构造函数。
	 * @param clientPrincipal 经过身份验证的客户端主体
	 * @param additionalParameters 附加参数
	 * @param appid AppID(码云Gitee client_id)
	 * @param code 授权码，<a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 * @param scope {@link OAuth2ParameterNames#SCOPE}，授权范围，<a href=
	 * "https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 */
	public OAuth2GiteeAuthenticationToken(Authentication clientPrincipal, Map<String, Object> additionalParameters,
			String appid, String code, String scope, String remoteAddress, String sessionId, String state,
			String binding) {
		super(OAuth2GiteeAuthenticationToken.GITEE, clientPrincipal, additionalParameters);
		Assert.hasText(code, "appid 不能为空");
		Assert.hasText(code, "code 不能为空");
		this.appid = appid;
		this.code = code;
		this.scope = scope;
		this.remoteAddress = remoteAddress;
		this.sessionId = sessionId;
		this.state = state;
		this.binding = binding;
	}

}
