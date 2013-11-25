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
package org.picketlink.identity.federation.web.servlets.saml;


import static org.picketlink.identity.federation.core.util.StringUtil.isNotNull;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.log4j.Logger;
import org.picketlink.identity.federation.api.saml.v2.metadata.KeyDescriptorMetaDataBuilder;
import org.picketlink.identity.federation.api.util.KeyUtil;
import org.picketlink.identity.federation.core.ErrorCodes;
import org.picketlink.identity.federation.core.config.*;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.interfaces.IMetadataProvider;
import org.picketlink.identity.federation.core.interfaces.TrustKeyConfigurationException;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.writers.SAMLMetadataWriter;
import org.picketlink.identity.federation.core.util.CoreConfigUtil;
import org.picketlink.identity.federation.core.util.StaxUtil;
import org.picketlink.identity.federation.core.util.XMLEncryptionUtil;
import org.picketlink.identity.federation.core.util.XMLSignatureUtil;
import org.picketlink.identity.federation.saml.v2.metadata.*;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType.EDTDescriptorChoiceType;
import org.picketlink.identity.federation.web.constants.GeneralConstants;
import org.picketlink.identity.federation.web.util.ConfigurationUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Metadata servlet for the IDP/SP
 *
 * @author Anil.Saldhana@redhat.com
 * @since Apr 22, 2009
 */
public class MetadataServletSP extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static Logger log = Logger.getLogger(MetadataServletSP.class);

    private final boolean trace = log.isTraceEnabled();

    private String configFileLocation = GeneralConstants.CONFIG_FILE_LOCATION;

    private transient MetadataProviderType metadataProviderType = null;

    private transient IMetadataProvider<?> metadataProvider = null;

    private transient EntitiesDescriptorType entitiesDescriptor;

    private transient EntityDescriptorType entityDescriptor;

    private String signingAlias = null;

    private String encryptingAlias = null;

    private TrustKeyManager keyManager;

    @SuppressWarnings("rawtypes")
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        ServletContext context = config.getServletContext();
        String configL = config.getInitParameter("configFile");
        if (isNotNull(configL))
            configFileLocation = configL;
        if (trace)
            log.trace("Config File Location=" + configFileLocation);
        InputStream is = context.getResourceAsStream(configFileLocation);
        if (is == null)
            throw new RuntimeException(ErrorCodes.RESOURCE_NOT_FOUND + configFileLocation + " missing");

        // Look for signing alias
        signingAlias = config.getInitParameter("signingAlias");
        encryptingAlias = config.getInitParameter("encryptingAlias");

        ProviderType providerType = getProviderType(is);

        metadataProviderType = providerType.getMetaDataProvider();
        String fqn = metadataProviderType.getClassName();
        Class<?> clazz = SecurityActions.loadClass(getClass(), fqn);
        try {
            metadataProvider = (IMetadataProvider) clazz.newInstance();
        } catch (InstantiationException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
        List<KeyValueType> keyValues = metadataProviderType.getOption();
        Map<String, String> options = new HashMap<String, String>();
        if (keyValues != null) {
            for (KeyValueType kvt : keyValues)
                options.put(kvt.getKey(), kvt.getValue());
        }
        metadataProvider.init(options);
            /*if (metadataProvider.isMultiple())
                throw new RuntimeException(ErrorCodes.NOT_IMPLEMENTED_YET + "Multiple Entities not currently supported");
            */
        /**
         * Since a metadata provider does not have access to the servlet context. It may be difficult to get to the resource
         * from the TCL.
         */
        String fileInjectionStr = metadataProvider.requireFileInjection();
        if (isNotNull(fileInjectionStr)) {
            metadataProvider.injectFileStream(context.getResourceAsStream(fileInjectionStr));
        }
        Object metadata = metadataProvider.getMetaData();
        if (metadata instanceof EntitiesDescriptorType) {
            entitiesDescriptor = (EntitiesDescriptorType) metadata;
        }else if (metadata instanceof EntityDescriptorType) {
            entityDescriptor = (EntityDescriptorType) metadata;
        } else {
            throw new RuntimeException(ErrorCodes.PARSING_ERROR+"Invalid metadata type");
        }

        // Get the trust manager information
        KeyProviderType keyProvider = providerType.getKeyProvider();
        signingAlias = keyProvider.getSigningAlias();
        String keyManagerClassName = keyProvider.getClassName();
        if (keyManagerClassName == null)
            throw new RuntimeException(ErrorCodes.NULL_VALUE + "KeyManager class name");

        clazz = SecurityActions.loadClass(getClass(), keyManagerClassName);

        
        try{
            this.keyManager = (TrustKeyManager) clazz.newInstance();

            List<AuthPropertyType> authProperties = CoreConfigUtil.getKeyProviderProperties(keyProvider);
            keyManager.setAuthProperties(authProperties);

            Certificate cert = keyManager.getCertificate(signingAlias);
            Element keyInfo = KeyUtil.getKeyInfo(cert);

            // TODO: Assume just signing key for now
            KeyDescriptorType keyDescriptor = KeyDescriptorMetaDataBuilder.createKeyDescriptor(keyInfo, null, 0, true, false);

            if (entitiesDescriptor != null)
                updateKeyDescriptors(entitiesDescriptor, keyDescriptor);
            else{
                updateKeyDescriptor(entityDescriptor,keyDescriptor);

            }
            // encryption
            if (encryptingAlias == null)
                encryptingAlias = signingAlias;
            cert = keyManager.getCertificate(encryptingAlias);
            keyInfo = KeyUtil.getKeyInfo(cert);

            keyDescriptor = KeyDescriptorMetaDataBuilder.createKeyDescriptor(keyInfo, null, 0, false, true);
            if (entitiesDescriptor != null)
                updateKeyDescriptors(entitiesDescriptor, keyDescriptor);
            else{
                updateKeyDescriptor(entityDescriptor,keyDescriptor);
                insertDigestAndSignature(entityDescriptor);
            }

        }catch(Exception e){
            throw  new RuntimeException(e);
        }

    }



    private ProviderType getProviderType(InputStream is) {
        ProviderType providerType  = null;
        if (is != null) {
            try {
                PicketLinkType picketLinkConfiguration = ConfigurationUtil.getConfiguration(is);
                providerType = picketLinkConfiguration.getIdpOrSP();
            } catch (ParsingException e) {
                throw new RuntimeException(e);
            }
        }
        return providerType;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType(JBossSAMLConstants.METADATA_MIME.get());
        OutputStream os = resp.getOutputStream();

        try {
            XMLStreamWriter streamWriter = StaxUtil.getXMLStreamWriter(os);
            SAMLMetadataWriter writer = new SAMLMetadataWriter(streamWriter);
            if (entitiesDescriptor != null)
                writer.writeEntitiesDescriptor(entitiesDescriptor);
            else
                writer.writeEntityDescriptor(entityDescriptor);

        } catch (ProcessingException e) {
            throw new ServletException(e);
        }
        /*
         * JAXBElement<?> jaxbEl = MetaDataBuilder.getObjectFactory().createEntityDescriptor(metadata); try {
         * MetaDataBuilder.getMarshaller().marshal(jaxbEl , os); } catch (Exception e) { throw new RuntimeException(e); }
         */
    }

    private void insertDigestAndSignature(EntityDescriptorType entityDescriptor) throws ServletException{
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            XMLStreamWriter streamWriter = StaxUtil.getXMLStreamWriter(baos);
            SAMLMetadataWriter writer = new SAMLMetadataWriter(streamWriter);
            writer.writeEntityDescriptor(entityDescriptor);
            Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            KeyPair keyPair = new KeyPair(keyManager.getCertificate(signingAlias).getPublicKey(), keyManager.getSigningKey());
            //Sign doc
            Element spssoDesc = doc.getDocumentElement(); //TODO: EXTRACT ONLY THE SPSSODESCRIPTOR!!!!
            XMLSignatureUtil.sign(spssoDesc,spssoDesc.getFirstChild(),keyPair,DigestMethod.SHA1,
                    SignatureMethod.RSA_SHA1,"",(X509Certificate) keyManager.getCertificate(signingAlias));
            //extract Signature
            entityDescriptor.setSignature(extractSignatureFromDoc(spssoDesc));
            System.out.println("*************************************DOOOC ************************************");
            System.out.println(getStringFromDocument(spssoDesc.getOwnerDocument()));
            System.out.println("*************************************/DOOOC ************************************");
        } catch (Exception e) {
            throw new ServletException(e);
        }

    }

    private Element extractSignatureFromDoc(Element doc) {
        return (Element) doc.getElementsByTagName("Signature").item(0);

    }

    //TODO:TEMPORANEO PER TESTARE SIGN RIMUOVERE!!!!!
    private void signEntityDescriptor(){

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            XMLStreamWriter streamWriter = StaxUtil.getXMLStreamWriter(baos);
            SAMLMetadataWriter writer = new SAMLMetadataWriter(streamWriter);
            writer.writeEntityDescriptor(entityDescriptor);
            Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            Node n= doc.getFirstChild();
            System.out.println(n.getLocalName());
            System.out.println(n.getNodeName());

            KeyPair keyPair = new KeyPair(keyManager.getCertificate(signingAlias).getPublicKey(), keyManager.getSigningKey());
            Element spssoDesc = doc.getDocumentElement();

            XMLSignatureUtil.sign(spssoDesc,spssoDesc.getFirstChild(),keyPair,DigestMethod.SHA1,
                    SignatureMethod.RSA_SHA1,"",(X509Certificate) keyManager.getCertificate(signingAlias));
            System.out.println(getStringFromDocument(spssoDesc.getOwnerDocument()));
        } catch (ProcessingException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (SAXException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (ParserConfigurationException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (IOException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (MarshalException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (TrustKeyConfigurationException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (GeneralSecurityException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (XMLSignatureException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (TransformerException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
    }
    private String getStringFromDocument(Document doc) throws TransformerException {
        DOMSource domSource = new DOMSource(doc);
        StringWriter writer = new StringWriter();
        StreamResult result = new StreamResult(writer);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.transform(domSource, result);
        return writer.toString();
    }
    //TODO: FINE TEMPORANEO


    private void updateKeyDescriptors(EntitiesDescriptorType entityId, KeyDescriptorType keyD){
        List<Object> entities =  entityId.getEntityDescriptor();
        for (Object obj : entities){
            updateKeyDescriptor((EntityDescriptorType) obj,keyD);

        }

    }

    private void updateKeyDescriptor(EntityDescriptorType entityD, KeyDescriptorType keyD) {
        List<EDTDescriptorChoiceType> objs = entityD.getChoiceType().get(0).getDescriptors();
        if (objs != null) {
            for (EDTDescriptorChoiceType choiceTypeDesc : objs) {
                AttributeAuthorityDescriptorType attribDescriptor = choiceTypeDesc.getAttribDescriptor();
                if (attribDescriptor != null)
                    attribDescriptor.addKeyDescriptor(keyD);
                AuthnAuthorityDescriptorType authnDescriptor = choiceTypeDesc.getAuthnDescriptor();
                if (authnDescriptor != null)
                    authnDescriptor.addKeyDescriptor(keyD);
                IDPSSODescriptorType idpDescriptor = choiceTypeDesc.getIdpDescriptor();
                if (idpDescriptor != null)
                    idpDescriptor.addKeyDescriptor(keyD);
                PDPDescriptorType pdpDescriptor = choiceTypeDesc.getPdpDescriptor();
                if (pdpDescriptor != null)
                    pdpDescriptor.addKeyDescriptor(keyD);
                RoleDescriptorType roleDescriptor = choiceTypeDesc.getRoleDescriptor();
                if (roleDescriptor != null)
                    roleDescriptor.addKeyDescriptor(keyD);
                SPSSODescriptorType spDescriptorType = choiceTypeDesc.getSpDescriptor();
                if (spDescriptorType != null)
                    spDescriptorType.addKeyDescriptor(keyD);

            }
        }
    }
}