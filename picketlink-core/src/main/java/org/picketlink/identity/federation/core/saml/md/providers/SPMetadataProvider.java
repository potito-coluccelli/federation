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
/**
 * Author: coluccelli@redhat.com
 */
package org.picketlink.identity.federation.core.saml.md.providers;

import org.picketlink.identity.federation.PicketLinkLogger;
import org.picketlink.identity.federation.PicketLinkLoggerFactory;
import org.picketlink.identity.federation.core.interfaces.IMetadataProvider;
import org.picketlink.identity.federation.saml.v2.metadata.EndpointType;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.IndexedEndpointType;
import org.picketlink.identity.federation.saml.v2.metadata.SPSSODescriptorType;

import java.io.InputStream;
import java.net.URI;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Map;


public class SPMetadataProvider extends AbstractMetadataProvider implements
        IMetadataProvider<EntityDescriptorType> {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();
    private static final String ENTITY_ID_KEY="EntityId";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private String entityId;
    private String logoutPage;
    private String bindingUri;
    private String serviceUrl;
    private String logoutResponseLocation;

    @Override
    public void init(Map<String, String> options) {
        super.init(options);
        entityId = options.get(ENTITY_ID_KEY);
        if (entityId == null)
            throw logger.optionNotSet("EntityId");
        logoutPage = options.get(MetadataProviderUtils.LOGOUT_URL);
        logoutResponseLocation = options.get(MetadataProviderUtils.LOGOUT_RESPONSE_LOCATION);
        bindingUri = options.get(MetadataProviderUtils.BINDING_URI);
        serviceUrl = options.get(MetadataProviderUtils.SERVICE_URL);
    }

    @Override
    public EntityDescriptorType getMetaData() {
        ArrayList<String> protocols = new ArrayList<String>();
        protocols.add(PROTOCOL);
        SPSSODescriptorType spSSO = new SPSSODescriptorType(protocols);
        spSSO.setAuthnRequestsSigned(true);
        spSSO.setWantAssertionsSigned(true);
        if (bindingUri!=null && logoutPage != null){
            EndpointType endpointType = new EndpointType(URI.create(bindingUri), URI.create(logoutPage));
            endpointType.setResponseLocation(URI.create(logoutResponseLocation));
            spSSO.addSingleLogoutService(endpointType);
        }
        spSSO.addAssertionConsumerService(new IndexedEndpointType(URI.create(bindingUri),URI.create(serviceUrl)));
        EntityDescriptorType.EDTDescriptorChoiceType edtDescChoice = new EntityDescriptorType.EDTDescriptorChoiceType(spSSO);
        EntityDescriptorType.EDTChoiceType edtChoice = EntityDescriptorType.EDTChoiceType.oneValue(edtDescChoice);

        EntityDescriptorType entityDescriptor = new EntityDescriptorType(entityId);
        entityDescriptor.addChoiceType(edtChoice);
        return entityDescriptor;
    }

    @Override
    public boolean isMultiple() {
        return false;
    }

    @Override
    public String requireFileInjection() {
        return null;
    }

    @Override
    public void injectFileStream(InputStream fileStream) {
    }

    @Override
    public void injectSigningKey(PublicKey publicKey) {
    }

    @Override
    public void injectEncryptionKey(PublicKey publicKey) {
    }
}
