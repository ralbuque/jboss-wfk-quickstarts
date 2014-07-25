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

import org.picketlink.common.util.DocumentUtil;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.util.JAXPValidationUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.picketlink.idm.credential.Token;
import org.w3c.dom.Document;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * @author Pedro Igor
 */
public class SAMLToken implements Token {

    private final AssertionType assertion;
    private final String assertionString;

    public SAMLToken(String assertionString) {
        InputStream responseStream = null;

        try {
            Document assertionDocument = DocumentUtil.getDocument(assertionString);
            SAMLParser samlParser = new SAMLParser();
            JAXPValidationUtil.checkSchemaValidation(assertionDocument);

            responseStream = DocumentUtil.getNodeAsStream(assertionDocument);
            this.assertion = (AssertionType) samlParser.parse(responseStream);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse SAML assertionString.", e);
        } finally {
            if (responseStream != null) {
                try {
                    responseStream.close();
                } catch (IOException ignore) {
                }
            }
        }

        this.assertionString = assertionString;
    }

    public List<String> getRoles() {
        List<String> roles = new ArrayList<String>();

        Set<StatementAbstractType> statements = this.assertion.getStatements();

        for (StatementAbstractType statement : statements) {
            if (statement instanceof AttributeStatementType) {
                AttributeStatementType attrStat = (AttributeStatementType) statement;
                List<AttributeStatementType.ASTChoiceType> attrs = attrStat.getAttributes();

                for (AttributeStatementType.ASTChoiceType attrChoice : attrs) {
                    AttributeType attr = attrChoice.getAttribute();

                    if (attr.getName().equalsIgnoreCase("role")) {
                        for (Object value : attr.getAttributeValue()) {
                            roles.add(value.toString());
                        }
                    }
                }
            }
        }

        return Collections.unmodifiableList(roles);
    }

    public String getUserName() {
        SubjectType.STSubType subType = this.assertion.getSubject().getSubType();

        return ((NameIDType) subType.getBaseID()).getValue();
    }

    public List<String> getGroups() {
        return Collections.emptyList();
    }

    public Date getExpiration() {
        return null;
    }

    public String getUserId() {
        return getUserName();
    }

    public String getRealm() {
        return this.assertion.getIssuer().getValue();
    }

    @Override
    public String getType() {
        return getClass().getName();
    }

    @Override
    public String getToken() {
        return this.assertionString;
    }
}
