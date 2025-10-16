package com.structurizr.onpremises.configuration;

import java.util.Properties;

class OidcConfigurer extends Configurer {


    public static final String DEFAULT_OIDC_SCOPE = "openid";
    public static final String DEFAULT_OIDC_ATTRIBUTE_USERNAME = "email";
    public static final String DEFAULT_OIDC_ATTRIBUTE_ROLES = "groups";

    OidcConfigurer(Properties properties) {
        super(properties);
    }

    void apply() {
        setDefault(StructurizrProperties.OIDC_CLIENT_PROVIDER_ISSUER_URI, "");
        setDefault(StructurizrProperties.OIDC_CLIENT_REGISTRATION_ID, "");
        setDefault(StructurizrProperties.OIDC_CLIENT_CLIENT_ID, "");
        setDefault(StructurizrProperties.OIDC_CLIENT_CLIENT_SECRET, "");
        setDefault(StructurizrProperties.OIDC_CLIENT_SCOPE, DEFAULT_OIDC_SCOPE);
        setDefault(StructurizrProperties.OIDC_ATTRIBUTE_USERNAME, DEFAULT_OIDC_ATTRIBUTE_USERNAME);
        setDefault(StructurizrProperties.OIDC_ATTRIBUTE_ROLE, DEFAULT_OIDC_ATTRIBUTE_ROLES);
    }


}