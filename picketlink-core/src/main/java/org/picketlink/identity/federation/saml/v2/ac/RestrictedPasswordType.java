//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vhudson-jaxb-ri-2.1-661
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a>
// Any modifications to this file will be lost upon recompilation of the source schema.
// Generated on: 2008.12.08 at 05:45:20 PM CST
//

package org.picketlink.identity.federation.saml.v2.ac;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>
 * Java class for RestrictedPasswordType complex type.
 *
 * <p>
 * The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="RestrictedPasswordType">
 *   &lt;complexContent>
 *     &lt;restriction base="{urn:oasis:names:tc:SAML:2.0:ac}PasswordType">
 *       &lt;sequence>
 *         &lt;element name="Length" type="{urn:oasis:names:tc:SAML:2.0:ac}RestrictedLengthType"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:ac}Generation" minOccurs="0"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:ac}Extension" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="ExternalVerification" type="{http://www.w3.org/2001/XMLSchema}anyURI" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 *
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RestrictedPasswordType")
public class RestrictedPasswordType extends PasswordType {

}
