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

import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.credential.Token;
import org.picketlink.idm.credential.storage.TokenCredentialStorage;
import org.picketlink.idm.model.Account;
import org.picketlink.idm.model.basic.Realm;
import org.picketlink.idm.model.basic.User;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import java.util.Date;

import static org.picketlink.idm.IDMMessages.MESSAGES;

/**
 * <p>A {@link org.picketlink.idm.credential.Token.Provider} to manage JSON Web Signature tokens.</p>
 *
 * @author Pedro Igor
 */
@ApplicationScoped
public class KeyCloakTokenProvider implements Token.Provider {

    @Inject
    private Instance<IdentityManager> identityManagerInstance;

    @Override
    public Account getAccount(Token token) {
        KeyCloakToken keyCloakToken = (KeyCloakToken) token;
        User account = new User(keyCloakToken.getUserName());

        account.setId(keyCloakToken.getUserId());

        Realm partition = new Realm(keyCloakToken.getRealm());

        partition.setId(partition.getName());

        account.setPartition(partition);

        return account;
    }

    @Override
    public Token create(Object value) {
        KeyCloakToken keyCloakToken = new KeyCloakToken(value.toString());
        Account account = getAccount(keyCloakToken);

        IdentityManager identityManager = getIdentityManager();

        identityManager.updateCredential(account, keyCloakToken);

        return keyCloakToken;
    }

    @Override
    public Token issue(Account account) {
        throw MESSAGES.notImplemented();
    }

    @Override
    public Token renew(Token token) {
        throw MESSAGES.notImplemented();
    }

    @Override
    public boolean validate(Token token) {
        KeyCloakToken keyCloakToken = (KeyCloakToken) token;

        Date expirationDate = keyCloakToken.getExpiration();

        System.out.println(expirationDate);
        System.out.println(new Date());

        boolean before = new Date().before(expirationDate);

        System.out.println(before);

        return before;
    }

    @Override
    public void invalidate(Account account) {
        getIdentityManager().removeCredential(account, TokenCredentialStorage.class);
    }

    @Override
    public boolean supports(Token token) {
        return Token.class.isInstance(token);
    }

    @Override
    public <T extends TokenCredentialStorage> T getTokenStorage(Account account, Token token) {
        return null;
    }

    private IdentityManager getIdentityManager() {
        return this.identityManagerInstance.get();
    }
}
