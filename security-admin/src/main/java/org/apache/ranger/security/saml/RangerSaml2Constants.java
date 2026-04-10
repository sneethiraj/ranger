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

/**
 * Configuration property keys for SAML 2.0 SP login (e.g. Keycloak as IdP).
 */
public final class RangerSaml2Constants {
    public static final String ENABLED          = "ranger.sso.saml.enabled";
    public static final String METADATA_URL     = "ranger.sso.saml.metadata.url";
    public static final String REGISTRATION_ID  = "ranger.sso.saml.registration.id";
    public static final String SP_ENTITY_ID     = "ranger.sso.saml.sp.entity.id";

    private RangerSaml2Constants() {
    }
}
