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

import org.picketlink.idm.config.AbstractIdentityStoreConfiguration;
import org.picketlink.idm.credential.Token;
import org.picketlink.idm.credential.handler.CredentialHandler;
import org.picketlink.idm.model.AttributedType;
import org.picketlink.idm.spi.ContextInitializer;
import org.picketlink.idm.spi.IdentityStore;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author Pedro Igor
 */
public class TokenIdentityStoreConfiguration extends AbstractIdentityStoreConfiguration {

    private final IdentityExtractor identityExtractor;
    private Token.Provider tokenProvider;

    protected TokenIdentityStoreConfiguration(
        Token.Provider tokenProvider,
        IdentityExtractor identityExtractor,
        Map<Class<? extends AttributedType>,
        Set<IdentityOperation>> supportedTypes,
        Map<Class<? extends AttributedType>,
            Set<IdentityOperation>>
            unsupportedTypes,
            List<ContextInitializer> contextInitializers,
            Map<String, Object> credentialHandlerProperties,
            Set<Class<? extends CredentialHandler>> credentialHandlers,
            boolean supportsAttribute,
            boolean supportsCredential,
            boolean supportsPermissions) {
        super(supportedTypes, unsupportedTypes, contextInitializers, credentialHandlerProperties, credentialHandlers, supportsAttribute, supportsCredential, supportsPermissions);
        this.identityExtractor = identityExtractor;
        this.tokenProvider = tokenProvider;
    }

    @Override
    public Class<? extends IdentityStore> getIdentityStoreType() {
        return TokenIdentityStore.class;
    }

    public IdentityExtractor getIdentityExtractor() {
        return this.identityExtractor;
    }

    public Token.Provider getTokenProvider() {
        return this.tokenProvider;
    }
}
