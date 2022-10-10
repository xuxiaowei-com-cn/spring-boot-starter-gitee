package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * 重定向 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class RedirectGiteeException extends GiteeException {

	public RedirectGiteeException(String errorCode) {
		super(errorCode);
	}

	public RedirectGiteeException(OAuth2Error error) {
		super(error);
	}

	public RedirectGiteeException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public RedirectGiteeException(OAuth2Error error, String message) {
		super(error, message);
	}

	public RedirectGiteeException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

	@Override
	public OAuth2Error getError() {
		return super.getError();
	}

}
