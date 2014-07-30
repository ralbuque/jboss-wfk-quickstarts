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

import org.picketlink.common.properties.Property;
import org.picketlink.common.properties.query.AnnotatedPropertyCriteria;
import org.picketlink.common.properties.query.PropertyQueries;
import org.picketlink.common.reflection.Reflections;
import org.picketlink.idm.IdentityManagementException;
import org.picketlink.idm.credential.Token;
import org.picketlink.idm.model.IdentityType;
import org.picketlink.idm.model.annotation.StereotypeProperty;

import javax.enterprise.context.ApplicationScoped;
import java.util.List;
import java.util.Set;

import static org.picketlink.idm.IDMMessages.MESSAGES;

/**
 * <p>A {@link org.picketlink.idm.credential.Token.Provider} to manage JSON Web Signature tokens.</p>
 *
 * @author Pedro Igor
 */
@ApplicationScoped
public class SAMLTokenConsumer implements Token.Consumer<SAMLAssertion> {

    @Override
    public <T extends IdentityType> T extractIdentity(SAMLAssertion token, Class<T> identityType, StereotypeProperty.Property stereotypeProperty, Object identifier) {
        if (token == null || token.getToken() == null) {
            throw MESSAGES.nullArgument("Token");
        }

        if (identityType == null) {
            throw MESSAGES.nullArgument("IdentityType");
        }

        if (stereotypeProperty == null) {
            throw MESSAGES.nullArgument("Identifier value");
        }

        if (identifier == null) {
            throw MESSAGES.nullArgument("Identifier value");
        }

        return extractIdentityTypeFromToken(token, identityType, stereotypeProperty, identifier);
    }

    @Override
    public boolean validate(SAMLAssertion token) {
        // all validation is done by the PicketLink Authenticator.
        return true;
    }

    @Override
    public Class<SAMLAssertion> getTokenType() {
        return SAMLAssertion.class;
    }

    private <T extends IdentityType> T extractIdentityTypeFromToken(SAMLAssertion SAMLToken, Class<T> identityType, StereotypeProperty.Property stereotypeProperty, Object identifier) {
        if (hasIdentityType(SAMLToken, stereotypeProperty, identifier)) {
            try {
                T identityTypeInstance = Reflections.newInstance(identityType);
                Property property = resolveProperty(identityType, stereotypeProperty);

                property.setValue(identityTypeInstance, identifier);

                return identityTypeInstance;
            } catch (Exception e) {
                throw new IdentityManagementException("Could not extract IdentityType [" + identityType + "] from Token [" + SAMLToken + "].", e);
            }
        }

        return null;
    }

    private Property resolveProperty(Class<? extends IdentityType> identityType, StereotypeProperty.Property stereotypeProperty) {
        List<Property<Object>> properties = PropertyQueries
            .createQuery(identityType)
            .addCriteria(new AnnotatedPropertyCriteria(StereotypeProperty.class))
            .getResultList();

        if (properties.isEmpty()) {
            throw new IdentityManagementException("IdentityType [" + identityType + "] does not have any property mapped with " + StereotypeProperty.class + ".");
        }

        for (Property property : properties) {
            StereotypeProperty propertyStereotypeProperty = property.getAnnotatedElement().getAnnotation(StereotypeProperty.class);

            if (stereotypeProperty.equals(propertyStereotypeProperty.value())) {
                return property;
            }
        }

        throw new IdentityManagementException("Could not resolve property in type [" + identityType + " for StereotypeProperty [" + stereotypeProperty + ".");
    }

    private boolean hasIdentityType(SAMLAssertion samlAssertion, StereotypeProperty.Property stereotypeProperty, Object identifier) {
        if (StereotypeProperty.Property.IDENTITY_ROLE_NAME.equals(stereotypeProperty)) {
            Set<String> roleNames = samlAssertion.getRoles();

            if (roleNames.contains(identifier)) {
                return true;
            }
        }

        if (StereotypeProperty.Property.IDENTITY_USER_NAME.equals(stereotypeProperty)) {
            String userName = samlAssertion.getSubject();

            if (userName != null && identifier.equals(userName)) {
                return true;
            }
        }

        return false;
    }
}
