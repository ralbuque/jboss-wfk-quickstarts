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

import org.jboss.quickstarts.wfk.contacts.security.authentication.KeyCloakJWT;
import org.picketlink.common.properties.Property;
import org.picketlink.common.properties.query.NamedPropertyCriteria;
import org.picketlink.common.properties.query.PropertyQueries;
import org.picketlink.idm.IdentityManagementException;
import org.picketlink.idm.credential.Credentials;
import org.picketlink.idm.credential.Token;
import org.picketlink.idm.credential.TokenCredential;
import org.picketlink.idm.credential.handler.TokenCredentialHandler;
import org.picketlink.idm.credential.handler.annotations.CredentialHandlers;
import org.picketlink.idm.credential.storage.CredentialStorage;
import org.picketlink.idm.internal.AbstractIdentityStore;
import org.picketlink.idm.model.Account;
import org.picketlink.idm.model.AttributedType;
import org.picketlink.idm.model.IdentityType;
import org.picketlink.idm.model.Partition;
import org.picketlink.idm.model.Relationship;
import org.picketlink.idm.model.annotation.StereotypeProperty;
import org.picketlink.idm.model.basic.Grant;
import org.picketlink.idm.model.basic.Realm;
import org.picketlink.idm.model.basic.Role;
import org.picketlink.idm.query.AttributeParameter;
import org.picketlink.idm.query.IdentityQuery;
import org.picketlink.idm.query.QueryParameter;
import org.picketlink.idm.query.RelationshipQuery;
import org.picketlink.idm.query.RelationshipQueryParameter;
import org.picketlink.idm.spi.CredentialStore;
import org.picketlink.idm.spi.IdentityContext;
import org.picketlink.idm.spi.PartitionStore;
import org.picketlink.json.jwt.JWTBuilder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Pedro Igor
 */
@CredentialHandlers({
    TokenCredentialHandler.class})
public class TokenIdentityStore extends AbstractIdentityStore<TokenIdentityStoreConfiguration>
    implements CredentialStore<TokenIdentityStoreConfiguration>,
    PartitionStore<TokenIdentityStoreConfiguration> {

    private final Map<String, Token> tokenRegistry = new HashMap<String, Token>();

    @Override
    public void validateCredentials(IdentityContext context, Credentials credentials) {
        super.validateCredentials(context, credentials);

        if (Credentials.Status.VALID.equals(credentials.getStatus())) {
            TokenCredential tokenCredential = (TokenCredential) credentials;
            Account account = tokenCredential.getValidatedAccount();
            tokenRegistry.put(account.getId(), tokenCredential.getToken());
        }
    }

    @Override
    protected void removeFromRelationships(IdentityContext context, IdentityType identityType) {

    }

    @Override
    protected void removeCredentials(IdentityContext context, Account account) {

    }

    @Override
    protected void updateAttributedType(IdentityContext context, AttributedType attributedType) {

    }

    @Override
    protected void removeAttributedType(IdentityContext context, AttributedType attributedType) {

    }

    @Override
    public <V extends IdentityType> List<V> fetchQueryResults(IdentityContext context, IdentityQuery<V> query) {
        ArrayList<V> identityTypes = new ArrayList<V>();

        if (Role.class.equals(query.getIdentityType())) {
            for (QueryParameter queryParameter : query.getParameters().keySet()) {
                AttributeParameter attributeParameter = (AttributeParameter) queryParameter;
                Property<Object> nameProperty = PropertyQueries
                    .createQuery(query.getIdentityType())
                    .addCriteria(new NamedPropertyCriteria(attributeParameter.getName()))
                    .getFirstResult();

                StereotypeProperty stereotypeProperty = nameProperty.getAnnotatedElement().getAnnotation(StereotypeProperty.class);

                if (stereotypeProperty.value().equals(StereotypeProperty.Property.IDENTITY_ROLE_NAME)) {
                    Object[] roleNameParameterValue = query.getParameter(attributeParameter);

                    if (roleNameParameterValue != null) {
                        identityTypes.add((V) new Role((String) roleNameParameterValue[0]));
                    }
                }
            }

        }

        return identityTypes;
    }

    @Override
    public <V extends Relationship> List<V> fetchQueryResults(IdentityContext context, RelationshipQuery<V> query) {
        ArrayList<V> relationships = new ArrayList<V>();

        if (Grant.class.equals(query.getRelationshipClass())) {
            Account assignee = null;
            Role role = null;

            for (QueryParameter queryParameter : query.getParameters().keySet()) {
                RelationshipQueryParameter relationshipQueryParameter = (RelationshipQueryParameter) queryParameter;
                Object[] parameterValues = query.getParameter(relationshipQueryParameter);
                Property<Object> property = PropertyQueries
                    .createQuery(query.getRelationshipClass())
                    .addCriteria(new NamedPropertyCriteria(relationshipQueryParameter.getName()))
                    .getFirstResult();

                StereotypeProperty stereotypeProperty = property.getAnnotatedElement().getAnnotation(StereotypeProperty.class);

                if (stereotypeProperty != null) {
                    if (StereotypeProperty.Property.RELATIONSHIP_GRANT_ASSIGNEE.equals(stereotypeProperty.value())) {
                        assignee = (Account) parameterValues[0];
                    }

                    if (StereotypeProperty.Property.RELATIONSHIP_GRANT_ROLE.equals(stereotypeProperty.value())) {
                        role = (Role) parameterValues[0];
                    }
                }
            }

            if (assignee == null) {
                throw new IdentityManagementException("Assignee can not be null when querying Grant relationships.");
            }

            if (role == null) {
                throw new IdentityManagementException("Role can not be null when querying Grant relationships.");
            }

            Token token = this.tokenRegistry.get(assignee.getId());
            KeyCloakJWT parsedToken = (KeyCloakJWT) new JWTBuilder(KeyCloakJWT.class).build(token.getToken());

            for (String roleFromToken : parsedToken.getRoles()) {
                if (roleFromToken.equals(role.getName())) {
                    relationships.add((V) new Grant(assignee, role));
                }
            }
        }

        return relationships;
    }

    @Override
    public void storeCredential(IdentityContext context, Account account, CredentialStorage storage) {

    }

    @Override
    public <T extends CredentialStorage> T retrieveCurrentCredential(IdentityContext context, Account account, Class<T> storageClass) {
        return null;
    }

    @Override
    public <T extends CredentialStorage> List<T> retrieveCredentials(IdentityContext context, Account account, Class<T> storageClass) {
        return null;
    }

    @Override
    public String getConfigurationName(IdentityContext identityContext, Partition partition) {
        return null;
    }

    @Override
    public <P extends Partition> P get(IdentityContext identityContext, Class<P> partitionClass, String name) {
        return (P) new Realm(Realm.DEFAULT_REALM);
    }

    @Override
    public <P extends Partition> List<P> get(IdentityContext identityContext, Class<P> partitionClass) {
        ArrayList<P> partitions = new ArrayList<P>();

        partitions.add((P) get(identityContext, Realm.class, Realm.DEFAULT_REALM));

        return partitions;
    }

    @Override
    public <P extends Partition> P lookupById(IdentityContext context, Class<P> partitionClass, String id) {
        return null;
    }

    @Override
    public void add(IdentityContext identityContext, Partition partition, String configurationName) {

    }

    @Override
    public void update(IdentityContext identityContext, Partition partition) {

    }

    @Override
    public void remove(IdentityContext identityContext, Partition partition) {

    }
}
