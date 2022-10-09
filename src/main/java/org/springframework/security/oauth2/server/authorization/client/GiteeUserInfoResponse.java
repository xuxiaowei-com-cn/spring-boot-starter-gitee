package org.springframework.security.oauth2.server.authorization.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.io.Serializable;

@Data
public class GiteeUserInfoResponse implements Serializable {

	private static final long serialVersionUID = 1L;

	@JsonProperty("gists_url")
	private String gistsUrl;

	@JsonProperty("repos_url")
	private String reposUrl;

	@JsonProperty("following_url")
	private String followingUrl;

	private String bio;

	@JsonProperty("created_at")
	private String createdAt;

	private String remark;

	private String login;

	private String type;

	private String blog;

	@JsonProperty("subscriptions_url")
	private String subscriptionsUrl;

	private String weibo;

	@JsonProperty("updated_at")
	private String updatedAt;

	private Long id;

	@JsonProperty("public_repos")
	private Long publicRepos;

	private String email;

	@JsonProperty("organizations_url")
	private String organizationsUrl;

	@JsonProperty("starred_url")
	private String starredUrl;

	@JsonProperty("followers_url")
	private String followersUrl;

	@JsonProperty("public_gists")
	private Long publicGists;

	private String url;

	@JsonProperty("received_events_url")
	private String receivedEventsUrl;

	private Long watched;

	private Long followers;

	@JsonProperty("avatar_url")
	private String avatarUrl;

	@JsonProperty("events_url")
	private String eventsUrl;

	@JsonProperty("html_url")
	private String htmlUrl;

	private Long following;

	private String name;

	private Long stared;

	private String message;

}
