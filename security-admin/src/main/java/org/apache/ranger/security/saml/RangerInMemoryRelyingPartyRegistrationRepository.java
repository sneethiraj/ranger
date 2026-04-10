package org.apache.ranger.security.saml;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

// Extended from org.springframework.security.saml2.provider.service.registration to avoid throwing error when empty registration list is received.

public class RangerInMemoryRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository, Iterable<RelyingPartyRegistration> {
    private final Map<String, RelyingPartyRegistration> byRegistrationId;

    public RangerInMemoryRelyingPartyRegistrationRepository(RelyingPartyRegistration... registrations) {
        this((Collection) Arrays.asList(registrations));
    }

    public RangerInMemoryRelyingPartyRegistrationRepository(Collection<RelyingPartyRegistration> registrations) {
        this.byRegistrationId = createMappingToIdentityProvider(registrations);
    }

    private static Map<String, RelyingPartyRegistration> createMappingToIdentityProvider(Collection<RelyingPartyRegistration> rps) {
        LinkedHashMap<String, RelyingPartyRegistration> result = new LinkedHashMap();

        for(RelyingPartyRegistration rp : rps) {
            Assert.notNull(rp, "relying party collection cannot contain null values");
            String key = rp.getRegistrationId();
            Assert.notNull(key, "relying party identifier cannot be null");
            Assert.isNull(result.get(key), () -> "relying party duplicate identifier '" + key + "' detected.");
            result.put(key, rp);
        }

        return Collections.unmodifiableMap(result);
    }

    public RelyingPartyRegistration findByRegistrationId(String id) {
        return (RelyingPartyRegistration)this.byRegistrationId.get(id);
    }

    public Iterator<RelyingPartyRegistration> iterator() {
        return this.byRegistrationId.values().iterator();
    }
}

