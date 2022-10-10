package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * 码云Gitee client_secret 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class SecretGiteeException extends GiteeException {

	public SecretGiteeException(String errorCode) {
		super(errorCode);
	}

	public SecretGiteeException(OAuth2Error error) {
		super(error);
	}

	public SecretGiteeException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public SecretGiteeException(OAuth2Error error, String message) {
		super(error, message);
	}

	public SecretGiteeException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

	@Override
	public OAuth2Error getError() {
		return super.getError();
	}

}
