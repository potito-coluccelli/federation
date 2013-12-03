/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.picketlink.identity.federation.core.saml.md.providers;

import org.picketlink.identity.federation.core.config.ProviderType;
import org.picketlink.identity.federation.core.config.SPType;

/**
 * Author: coluccelli@redhat.com
 */

public class MetadataProviderUtils {
    public static final String BINDING_URI = "BindingURI";
    public static final String SERVICE_URL = "ServiceURL";
    public static final String LOGOUT_URL = "LogoutUrl";
    public static final String LOGOUT_RESPONSE_LOCATION = "LogoutResponseLocation";

    public static String getLogoutURL(ProviderType providerType) {
        if (providerType instanceof SPType){
            SPType spType = (SPType) providerType;
            return spType.getLogoutUrl();
        }
        return null;
    }

    public static String getServiceURL(ProviderType providerType) {
        if (providerType instanceof SPType){
            SPType spType = (SPType) providerType;
            return spType.getServiceURL();
        }
        //TODO: Add support for IDP
        return null;
    }

    public static String getBindingURI(ProviderType providerType) {
        if (providerType instanceof SPType){//TODO: Add support for IDP
            SPType spType = (SPType) providerType;
            if (spType.getBindingType().equals("POST"))
                return "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
            if (spType.getBindingType().equals("REDIRECT"))
                return "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-REDIRECT";
        }
        return null;
    }
    public static String getLogoutResponseLocation(ProviderType providerType){
         if (providerType instanceof SPType){
            SPType spType = (SPType) providerType;
            return spType.getLogoutResponseLocation();
        }
        return null;
    }
}
