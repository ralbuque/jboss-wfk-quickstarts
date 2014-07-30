/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.quickstarts.wfk.contacts.security.authentication;

import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.util.JAXPValidationUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.picketlink.idm.credential.AbstractToken;
import org.w3c.dom.Document;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.picketlink.common.util.DocumentUtil.getDocument;
import static org.picketlink.common.util.DocumentUtil.getNodeAsStream;

/**
 * <p>A {@link org.picketlink.idm.credential.Token} that represents a SAML v2 Assertion.</p>
 *
 * @author Pedro Igor
 */
public class SAMLAssertion extends AbstractToken {

    private static final String ROLE_ATTRIBUTE_NAME = "role";

    private final AssertionType assertion;

    public SAMLAssertion(String assertionString) {
        super(assertionString);
        this.assertion = parseAssertion(assertionString);
    }

    @Override
    public String getSubject() {
        SubjectType.STSubType subType = this.assertion.getSubject().getSubType();

        return ((NameIDType) subType.getBaseID()).getValue();
    }

    /**
     * <p>Returns a {@link java.util.Set} containing all values for an attribute.</p>
     *
     * @param attributeName The name of the attribute.
     *
     * @return A {@link java.util.Set} containing all values for an attribute or an empty one of no attribute with the given name exists.
     */
    public Set<String> getAttribute(String attributeName) {
        Set<String> attributeValues = new HashSet<String>();

        Set<StatementAbstractType> statements = this.assertion.getStatements();

        for (StatementAbstractType statement : statements) {
            if (statement instanceof AttributeStatementType) {
                AttributeStatementType attrStat = (AttributeStatementType) statement;
                List<AttributeStatementType.ASTChoiceType> attrs = attrStat.getAttributes();

                for (AttributeStatementType.ASTChoiceType attrChoice : attrs) {
                    AttributeType attr = attrChoice.getAttribute();

                    if (attr.getName().equalsIgnoreCase(attributeName)) {
                        for (Object value : attr.getAttributeValue()) {
                            attributeValues.add(value.toString());
                        }
                    }
                }
            }
        }

        return Collections.unmodifiableSet(attributeValues);
    }

    /**
     * <p>Returns a {@link java.util.Set} containing all roles declared in the assertion.</p>
     *
     * @return A {@link java.util.Set} containing all roles declared in the assertion or empty if there is no role.
     */
    public Set<String> getRoles() {
        return getAttribute(ROLE_ATTRIBUTE_NAME);
    }

    private AssertionType parseAssertion(String assertionString) {
        InputStream responseStream = null;

        try {
            Document assertionDocument = getDocument(assertionString);
            SAMLParser samlParser = new SAMLParser();
            JAXPValidationUtil.checkSchemaValidation(assertionDocument);

            responseStream = getNodeAsStream(assertionDocument);
            return (AssertionType) samlParser.parse(responseStream);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse SAML Assertion.", e);
        } finally {
            if (responseStream != null) {
                try {
                    responseStream.close();
                } catch (IOException ignore) {
                }
            }
        }
    }
}
