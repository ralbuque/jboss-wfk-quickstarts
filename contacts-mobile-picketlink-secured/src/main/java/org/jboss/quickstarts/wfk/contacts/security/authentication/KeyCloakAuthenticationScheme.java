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

import org.keycloak.KeycloakSecurityContext;
import org.picketlink.authentication.web.TokenAuthenticationScheme;
import org.picketlink.credential.DefaultLoginCredentials;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.credential.TokenCredential;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Pedro Igor
 */
public class KeyCloakAuthenticationScheme extends TokenAuthenticationScheme {

    @Inject
    private Instance<IdentityManager> identityManagerInstance;

    @Override
    protected void extractTokenFromRequest(HttpServletRequest request, DefaultLoginCredentials creds) {
        creds.setCredential(new TokenCredential(extractKeyCloakToken(request)));
    }

    private KeyCloakToken extractKeyCloakToken(HttpServletRequest request) {
        KeyCloakToken token = null;
        KeycloakSecurityContext session = (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());

        if (session != null) {
            token = new KeyCloakToken(session.getTokenString());
        }
        return token;
    }

    @Override
    public boolean postAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException {
        IdentityManager identityManager = this.identityManagerInstance.get();
        KeyCloakToken keyCloakToken = extractKeyCloakToken(request);

        identityManager.updateCredential(getIdentity().getAccount(), keyCloakToken);

        return true;
    }
}
