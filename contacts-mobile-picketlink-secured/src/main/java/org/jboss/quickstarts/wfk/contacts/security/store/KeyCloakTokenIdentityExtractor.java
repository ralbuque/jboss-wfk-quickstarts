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
package org.jboss.quickstarts.wfk.contacts.security.store;

import org.jboss.quickstarts.wfk.contacts.security.authentication.KeyCloakToken;
import org.jboss.quickstarts.wfk.contacts.security.authentication.KeyCloakTokenProvider;
import org.picketlink.common.properties.Property;
import org.picketlink.common.properties.query.AnnotatedPropertyCriteria;
import org.picketlink.common.properties.query.PropertyQueries;
import org.picketlink.common.reflection.Reflections;
import org.picketlink.idm.IdentityManagementException;
import org.picketlink.idm.credential.Token;
import org.picketlink.idm.model.IdentityType;
import org.picketlink.idm.model.annotation.StereotypeProperty;

import javax.inject.Inject;
import java.util.List;

import static org.picketlink.idm.IDMMessages.MESSAGES;

/**
 * @author Pedro Igor
 */
public class KeyCloakTokenIdentityExtractor implements IdentityExtractor {

    @Inject
    private KeyCloakTokenProvider tokenProvider;

    @Override
    public IdentityType extractIdentity(Token token, Class<? extends IdentityType> identityType, StereotypeProperty.Property stereotypeProperty, Object identifier) {
        if (token == null || token.getToken() == null) {
            throw MESSAGES.nullArgument("Token");
        }

        KeyCloakToken keyCloakToken;

        try {
            keyCloakToken = (KeyCloakToken) token;
        } catch (Exception e) {
            throw new IdentityManagementException("Token is not a KeyCloakToken.", e);
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

        if (this.tokenProvider == null) {
            throw MESSAGES.nullArgument("TokenProvider");
        }

        return extractIdentityTypeFromToken(keyCloakToken, identityType, stereotypeProperty, identifier);
    }

    private IdentityType extractIdentityTypeFromToken(KeyCloakToken keyCloakToken, Class<? extends IdentityType> identityType, StereotypeProperty.Property stereotypeProperty, Object identifier) {
        if (hasIdentityType(keyCloakToken, stereotypeProperty, identifier)) {
            try {
                IdentityType identityTypeInstance = Reflections.newInstance(identityType);
                Property property = resolveProperty(identityType, stereotypeProperty);

                property.setValue(identityTypeInstance, identifier);

                return identityTypeInstance;
            } catch (Exception e) {
                throw new IdentityManagementException("Could not extract IdentityType [" + identityType + "] from Token [" + keyCloakToken + "].", e);
            }
        }

        return null;
    }

    //TODO: reuse
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

    private boolean hasIdentityType(KeyCloakToken keyCloakToken, StereotypeProperty.Property stereotypeProperty, Object identifier) {
        if (StereotypeProperty.Property.IDENTITY_ROLE_NAME.equals(stereotypeProperty)) {
            List<String> roleNames = keyCloakToken.getRoles();

            if (roleNames.contains(identifier)) {
                return true;
            }
        }

        if (StereotypeProperty.Property.IDENTITY_GROUP_NAME.equals(stereotypeProperty)) {
            List<String> groupNames = keyCloakToken.getGroups();

            if (groupNames.contains(identifier)) {
                return true;
            }
        }

        if (StereotypeProperty.Property.IDENTITY_USER_NAME.equals(stereotypeProperty)) {
            String userName = keyCloakToken.getUserName();

            if (userName != null && identifier.equals(userName)) {
                return true;
            }
        }

        return false;
    }
}
