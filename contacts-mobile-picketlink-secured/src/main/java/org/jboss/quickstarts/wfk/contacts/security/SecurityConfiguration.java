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

import org.jboss.quickstarts.wfk.contacts.security.authentication.PicketLinkSAMLAuthenticationScheme;
import org.picketlink.annotations.PicketLink;
import org.picketlink.authentication.web.HTTPAuthenticationScheme;
import org.picketlink.config.SecurityConfigurationBuilder;
import org.picketlink.event.SecurityConfigurationEvent;

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
    private PicketLinkSAMLAuthenticationScheme tokenAuthenticationScheme;

    public void configureIdentityManagement(@Observes SecurityConfigurationEvent event) {
        SecurityConfigurationBuilder builder = event.getBuilder();

        builder
            .idmConfig()
                .named("default.config")
                    .stores()
                        .token()
                            .supportAllFeatures();
    }

    @Produces
    @PicketLink
    public HTTPAuthenticationScheme configureTokenAuthenticationScheme() {
        return this.tokenAuthenticationScheme;
    }
}
