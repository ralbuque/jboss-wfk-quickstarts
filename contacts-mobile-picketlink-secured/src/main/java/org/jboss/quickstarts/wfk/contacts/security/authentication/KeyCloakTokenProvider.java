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

import org.picketlink.idm.credential.Token;
import org.picketlink.idm.credential.storage.TokenCredentialStorage;
import org.picketlink.idm.model.Account;
import org.picketlink.idm.model.basic.User;
import org.picketlink.json.jwt.JWTBuilder;

import javax.enterprise.context.ApplicationScoped;
import java.util.Date;

/**
 * <p>A {@link org.picketlink.idm.credential.Token.Provider} to manage JSON Web Signature tokens.</p>
 *
 * @author Pedro Igor
 */
@ApplicationScoped
public class KeyCloakTokenProvider implements Token.Provider {

    @Override
    public Account getAccount(Token token) {
        KeyCloakJWT keyCloakJWT = unMarshall(token.getToken());

        User user = new User(keyCloakJWT.getUserName());

        user.setId(keyCloakJWT.getSubject());

        return user;
    }

    @Override
    public Token create(Object value) {
        return new Token(value.toString());
    }

    @Override
    public Token issue(Account account) {
        return null;
    }

    @Override
    public Token renew(Token token) {
        return null;
    }

    @Override
    public boolean validate(Token token) {
        KeyCloakJWT keyCloakJWT = unMarshall(token.getToken());

        Date expirationDate = new Date(keyCloakJWT.getExpiration());

        return expirationDate.before(new Date());
    }

    @Override
    public void invalidate(Account account) {
        issue(account);
    }

    @Override
    public boolean supports(Token token) {
        return Token.class.isInstance(token);
    }

    @Override
    public <T extends TokenCredentialStorage> T getTokenStorage(Account account, Token token) {
        return null;
    }

    private KeyCloakJWT unMarshall(Object value) {
        return (KeyCloakJWT) new JWTBuilder(KeyCloakJWT.class).build(value.toString());
    }
}
