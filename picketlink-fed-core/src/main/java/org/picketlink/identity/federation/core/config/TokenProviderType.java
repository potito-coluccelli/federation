//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vJAXB 2.1.10 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema.  
// Generated on: 2009.09.03 at 01:21:42 PM BRT  
//


package org.picketlink.identity.federation.core.config;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for TokenProviderType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TokenProviderType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Property" type="{urn:picketlink:identity-federation:config:1.0}KeyValueType" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="ProviderClass" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="TokenType" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="TokenElement" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="TokenElementNS" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TokenProviderType", propOrder = {
    "property"
})
public class TokenProviderType {

    @XmlElement(name = "Property")
    protected List<KeyValueType> property;
    @XmlAttribute(name = "ProviderClass", required = true)
    protected String providerClass;
    @XmlAttribute(name = "TokenType", required = true)
    protected String tokenType;
    @XmlAttribute(name = "TokenElement", required = true)
    protected String tokenElement;
    @XmlAttribute(name = "TokenElementNS", required = true)
    protected String tokenElementNS;

    /**
     * Gets the value of the property property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the property property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getProperty().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link KeyValueType }
     * 
     * 
     */
    public List<KeyValueType> getProperty() {
        if (property == null) {
            property = new ArrayList<KeyValueType>();
        }
        return this.property;
    }

    /**
     * Gets the value of the providerClass property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getProviderClass() {
        return providerClass;
    }

    /**
     * Sets the value of the providerClass property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setProviderClass(String value) {
        this.providerClass = value;
    }

    /**
     * Gets the value of the tokenType property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTokenType() {
        return tokenType;
    }

    /**
     * Sets the value of the tokenType property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTokenType(String value) {
        this.tokenType = value;
    }

    /**
     * Gets the value of the tokenElement property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTokenElement() {
        return tokenElement;
    }

    /**
     * Sets the value of the tokenElement property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTokenElement(String value) {
        this.tokenElement = value;
    }

    /**
     * Gets the value of the tokenElementNS property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTokenElementNS() {
        return tokenElementNS;
    }

    /**
     * Sets the value of the tokenElementNS property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTokenElementNS(String value) {
        this.tokenElementNS = value;
    }

}