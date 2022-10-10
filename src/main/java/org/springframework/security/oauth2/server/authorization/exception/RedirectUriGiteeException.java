package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * 码云Gitee redirectUri 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class RedirectUriGiteeException extends GiteeException {

	public RedirectUriGiteeException(String errorCode) {
		super(errorCode);
	}

	public RedirectUriGiteeException(OAuth2Error error) {
		super(error);
	}

	public RedirectUriGiteeException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public RedirectUriGiteeException(OAuth2Error error, String message) {
		super(error, message);
	}

	public RedirectUriGiteeException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

	@Override
	public OAuth2Error getError() {
		return super.getError();
	}

}
