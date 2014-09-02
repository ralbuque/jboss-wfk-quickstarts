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

import org.picketlink.idm.credential.AbstractTokenConsumer;

import javax.enterprise.context.ApplicationScoped;
import java.util.Set;

import static java.util.Collections.emptySet;

/**
 * <p>A {@link org.picketlink.idm.credential.Token.Provider} to manage JSON Web Signature tokens.</p>
 *
 * @author Pedro Igor
 */
@ApplicationScoped
public class SAMLTokenConsumer extends AbstractTokenConsumer<SAMLAssertion> {

    @Override
    public boolean validate(SAMLAssertion token) {
        // all validation is done by the PicketLink Authenticator.
        return true;
    }

    @Override
    public Class<SAMLAssertion> getTokenType() {
        return SAMLAssertion.class;
    }

    @Override
    protected String extractSubject(SAMLAssertion token) {
        return token.getSubject();
    }

    @Override
    protected Set<String> extractRoles(SAMLAssertion token) {
        return token.getRoles();
    }

    @Override
    protected Set<String> extractGroups(SAMLAssertion token) {
        return emptySet();
    }
}
