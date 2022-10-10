package org.springframework.security.oauth2.core.endpoint;

/**
 * 码云Gitee 参数名称
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2ParameterNames 在 OAuth 参数注册表中定义并由授权端点、令牌端点和令牌撤销端点使用的标准和自定义（非标准）参数名称。
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public interface OAuth2GiteeParameterNames {

	/**
	 * AppID(码云Gitee client_id)
	 *
	 * @see <a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 */
	String APPID = "appid";

	/**
	 * @see OAuth2ParameterNames#CODE
	 *
	 * @see <a href="https://gitee.com/api/v5/oauth_doc">OAuth文档</a>
	 */
	String CODE = "code";

	/**
	 * 远程地址
	 */
	String REMOTE_ADDRESS = "remote_address";

	/**
	 * Session ID
	 */
	String SESSION_ID = "session_id";

}
