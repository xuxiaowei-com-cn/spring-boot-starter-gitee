package org.springframework.security.oauth2.server.authorization.web.authentication;

/**
 * 码云Gitee OAuth 2.0 协议端点的实用方法
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2GiteeEndpointUtils {

	/**
	 * 码云Gitee网页开发 /网页授权
	 */
	public static final String AUTH_CODE2SESSION_URI = "https://gitee.com/api/v5/oauth_doc";

	/**
	 * 错误代码
	 */
	public static final String ERROR_CODE = "C10000";

	/**
	 * 无效错误代码
	 */
	public static final String INVALID_ERROR_CODE = "C20000";

}
