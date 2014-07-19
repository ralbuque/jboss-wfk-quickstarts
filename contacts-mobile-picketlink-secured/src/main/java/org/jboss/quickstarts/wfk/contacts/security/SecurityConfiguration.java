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
package org.jboss.quickstarts.wfk.contacts.security;

import org.jboss.quickstarts.wfk.contacts.security.authentication.KeyCloakTokenProvider;
import org.jboss.quickstarts.wfk.contacts.security.store.TokenIdentityStoreConfiguration;
import org.jboss.quickstarts.wfk.contacts.security.store.TokenIdentityStoreConfigurationBuilder;
import org.picketlink.annotations.PicketLink;
import org.picketlink.authentication.web.TokenAuthenticationScheme;
import org.picketlink.config.SecurityConfigurationBuilder;
import org.picketlink.event.SecurityConfigurationEvent;
import org.picketlink.idm.PartitionManager;
import org.picketlink.idm.config.IdentityConfigurationBuilder;
import org.picketlink.idm.credential.handler.TokenCredentialHandler;
import org.picketlink.idm.internal.DefaultPartitionManager;
import org.picketlink.idm.model.basic.Grant;
import org.picketlink.idm.model.basic.Role;
import org.picketlink.idm.model.basic.User;
import org.picketlink.internal.EEJPAContextInitializer;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;

/**
 * <p>This class is responsible to enable the {@link org.picketlink.authentication.web.TokenAuthenticationScheme}.</p>
 *
 * @author Pedro Igor
 */
@ApplicationScoped
public class SecurityConfiguration {

    @Inject
    private KeyCloakTokenProvider tokenProvider;

    @Inject
    private EEJPAContextInitializer contextInitializer;

    @Inject
    private TokenAuthenticationScheme tokenAuthenticationScheme;

    @Produces
    @PicketLink
    public TokenAuthenticationScheme configureTokenAuthenticationScheme() {
        return this.tokenAuthenticationScheme;
    }

    public void configureIdentityManagement(@Observes SecurityConfigurationEvent event) {
        SecurityConfigurationBuilder builder = event.getBuilder();

        builder
            .identity()
            .stateless();
    }

    @Produces
    @PicketLink
    public PartitionManager producePartitionManager() {
        IdentityConfigurationBuilder builder = new IdentityConfigurationBuilder();

        builder
            .named("default.config")
                .stores()
                    .add(TokenIdentityStoreConfiguration.class, TokenIdentityStoreConfigurationBuilder.class)
                        .setCredentialHandlerProperty(TokenCredentialHandler.TOKEN_PROVIDER, this.tokenProvider)
                        .supportType(User.class, Role.class)
                        .supportGlobalRelationship(Grant.class)
                        .supportCredentials(true)
                        .supportPermissions(false)
                        .supportAttributes(false);

        return new DefaultPartitionManager(builder.buildAll());
    }
}
