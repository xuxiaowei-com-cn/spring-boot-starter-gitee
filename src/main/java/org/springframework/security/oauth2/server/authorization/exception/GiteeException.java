package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * 码云Gitee父异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class GiteeException extends OAuth2AuthenticationException {

	public GiteeException(String errorCode) {
		super(errorCode);
	}

	public GiteeException(OAuth2Error error) {
		super(error);
	}

	public GiteeException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public GiteeException(OAuth2Error error, String message) {
		super(error, message);
	}

	public GiteeException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

	@Override
	public OAuth2Error getError() {
		return super.getError();
	}

}
