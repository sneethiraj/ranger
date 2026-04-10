/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.ranger.security.saml;

import org.apache.commons.lang3.StringUtils;
import org.apache.ranger.common.PropertiesUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationRequestFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.Collections;

/**
 * SAML 2.0 service-provider filters and supporting beans for Keycloak (or any IdP
 * exposing standard SAML metadata). Disabled unless {@value RangerSaml2Constants#ENABLED} is true.
 */
@Configuration
@DependsOn("propertyConfigurer")
public class RangerSaml2Configuration {
    private static final Logger LOG = LoggerFactory.getLogger(RangerSaml2Configuration.class);

    private static final Filter SAML_NOOP_FILTER = new Filter() {
        @Override
        public void init(FilterConfig filterConfig) {
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
            chain.doFilter(request, response);
        }

        @Override
        public void destroy() {
        }
    };

    public static boolean isSaml2Enabled() {
        return PropertiesUtil.getBooleanProperty(RangerSaml2Constants.ENABLED, false);
    }

    @Bean
    public RelyingPartyRegistrationRepository rangerSaml2RelyingPartyRegistrationRepository() {
        if (!isSaml2Enabled()) {
            return new RangerInMemoryRelyingPartyRegistrationRepository(Collections.emptyList());
        }

        String metadataUrl    = StringUtils.trimToEmpty(PropertiesUtil.getProperty(RangerSaml2Constants.METADATA_URL));
        String spEntityId     = StringUtils.trimToEmpty(PropertiesUtil.getProperty(RangerSaml2Constants.SP_ENTITY_ID));
        String registrationId = StringUtils.trimToEmpty(PropertiesUtil.getProperty(RangerSaml2Constants.REGISTRATION_ID, "keycloak"));

        if (metadataUrl.isEmpty() || spEntityId.isEmpty()) {
            LOG.error("SAML SSO is enabled but {} and/or {} is not set; no relying party will be registered.", RangerSaml2Constants.METADATA_URL, RangerSaml2Constants.SP_ENTITY_ID);

            return new RangerInMemoryRelyingPartyRegistrationRepository(Collections.emptyList());
        }

        try {
            RelyingPartyRegistration registration = RelyingPartyRegistrations.fromMetadataLocation(metadataUrl)
                    .registrationId(registrationId)
                    .entityId(spEntityId)
                    .assertionConsumerServiceLocation("{baseUrl}/login/saml2/sso/{registrationId}")
                    .build();

            LOG.info("SAML relying party registered: registrationId={}, spEntityId={}", registrationId, spEntityId);

            return new RangerInMemoryRelyingPartyRegistrationRepository(registration);
        } catch (Exception e) {
            LOG.error("Failed to build SAML relying party registration from metadata URL {}", metadataUrl, e);

            return new RangerInMemoryRelyingPartyRegistrationRepository();
        }
    }

    @Bean(name = "rangerSamlAuthenticationManager")
    public AuthenticationManager rangerSamlAuthenticationManager() {
        return new ProviderManager(Collections.singletonList(new OpenSaml4AuthenticationProvider()));
    }

    @Bean
    public AuthenticationSuccessHandler rangerSamlAuthenticationSuccessHandler() {
        SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();

        handler.setDefaultTargetUrl("/dashboard.jsp");
        handler.setAlwaysUseDefaultTargetUrl(false);

        return handler;
    }

    @Bean(name = "rangerSaml2RequestFilter")
    public Filter rangerSaml2RequestFilter(RelyingPartyRegistrationRepository rangerSaml2RelyingPartyRegistrationRepository) {
        if (!isSaml2Enabled()) {
            return SAML_NOOP_FILTER;
        }

        return new Saml2WebSsoAuthenticationRequestFilter(rangerSaml2RelyingPartyRegistrationRepository);
    }

    @Bean(name = "rangerSaml2ResponseFilter")
    public Filter rangerSaml2ResponseFilter(
            RelyingPartyRegistrationRepository rangerSaml2RelyingPartyRegistrationRepository,
            @Qualifier("rangerSamlAuthenticationManager") AuthenticationManager rangerSamlAuthenticationManager,
            AuthenticationSuccessHandler rangerSamlAuthenticationSuccessHandler) {
        if (!isSaml2Enabled()) {
            return SAML_NOOP_FILTER;
        }

        Saml2WebSsoAuthenticationFilter filter = new Saml2WebSsoAuthenticationFilter(rangerSaml2RelyingPartyRegistrationRepository);

        filter.setAuthenticationManager(rangerSamlAuthenticationManager);
        filter.setAuthenticationSuccessHandler(rangerSamlAuthenticationSuccessHandler);

        return filter;
    }
}
