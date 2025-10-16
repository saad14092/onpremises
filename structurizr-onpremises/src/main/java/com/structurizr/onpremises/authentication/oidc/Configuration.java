package com.structurizr.onpremises.authentication.oidc;

import com.structurizr.onpremises.configuration.StructurizrProperties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

@org.springframework.context.annotation.Configuration
@EnableWebSecurity
public class Configuration {

	private static final Log log = LogFactory.getLog(Configuration.class);


	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {
		http
			.authorizeHttpRequests(authorize -> authorize
					.requestMatchers(new AntPathRequestMatcher("/api/**")).permitAll()
					.anyRequest().authenticated()
			)
			.csrf(csrf -> csrf.disable())
			.oauth2Login(withDefaults())
			.logout(logout -> logout.logoutUrl("/signout")
					.logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository)));
		return http.build();
	}

	@Bean
	public ClientRegistrationRepository clientRegistrationRepository() {
		return new InMemoryClientRegistrationRepository(this.oidcClientRegistration());
	}

	@Bean
	public OAuth2AuthorizedClientService authorizedClientService(
			ClientRegistrationRepository clientRegistrationRepository) {
		return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
	}

	@Bean
	public OAuth2AuthorizedClientRepository authorizedClientRepository(
			OAuth2AuthorizedClientService authorizedClientService) {
		return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
	}

	private ClientRegistration oidcClientRegistration() {
		String registrationId = com.structurizr.onpremises.configuration.Configuration
				.getInstance().getProperty(StructurizrProperties.OIDC_CLIENT_REGISTRATION_ID);
		String issuerUri = com.structurizr.onpremises.configuration.Configuration
				.getInstance().getProperty(StructurizrProperties.OIDC_CLIENT_PROVIDER_ISSUER_URI);
		String clientId = com.structurizr.onpremises.configuration.Configuration
				.getInstance().getProperty(StructurizrProperties.OIDC_CLIENT_CLIENT_ID);
		String clientSecret = com.structurizr.onpremises.configuration.Configuration
				.getInstance().getProperty(StructurizrProperties.OIDC_CLIENT_CLIENT_SECRET);
		String scope = com.structurizr.onpremises.configuration.Configuration
				.getInstance().getProperty(StructurizrProperties.OIDC_CLIENT_SCOPE);
		log.debug("Configuring OIDC authentication...");
		log.debug(StructurizrProperties.OIDC_CLIENT_REGISTRATION_ID + ": " + registrationId);
		log.debug(StructurizrProperties.OIDC_CLIENT_PROVIDER_ISSUER_URI + ": " + issuerUri);
		log.debug(StructurizrProperties.OIDC_CLIENT_CLIENT_ID + ": " + clientId);
		log.debug(StructurizrProperties.OIDC_CLIENT_SCOPE + ": " + scope);

		return ClientRegistrations.fromOidcIssuerLocation(issuerUri)
				.registrationId(registrationId)
				.clientId(clientId)
				.clientSecret(clientSecret)
				.scope(scope)
				.build();
	}

	private LogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
		OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
				new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);

		oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");

		return oidcLogoutSuccessHandler;
	}

}