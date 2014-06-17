/*
 * JBoss, Home of Professional Open Source
 * Copyright 2014, Red Hat, Inc. and/or its affiliates, and individual
 * contributors by the @authors tag. See the copyright.txt in the
 * distribution for a full listing of individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.quickstarts.wfk.contacts.security;

import org.picketlink.event.PartitionManagerCreateEvent;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.PartitionManager;
import org.picketlink.idm.RelationshipManager;
import org.picketlink.idm.config.SecurityConfigurationException;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.model.Attribute;
import org.picketlink.idm.model.basic.Realm;
import org.picketlink.idm.model.basic.Role;
import org.picketlink.idm.model.basic.User;

import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.enterprise.event.Observes;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import static org.picketlink.idm.model.basic.BasicModel.getRole;
import static org.picketlink.idm.model.basic.BasicModel.getUser;
import static org.picketlink.idm.model.basic.BasicModel.grantRole;

/**
 * <p>This EJB is responsible to initialize PicketLink Identity Management with some initial/default data, such as
 * users and roles.</p>
 *
 * <p>Usually, you don't need it in your application because your users and roles are created from a specific functionality
 * in your application. In this case, we just create some default users, roles and how they relate with each other in other to
 * demonstrate some security features.</p>
 *
 * <p>During initialization, the default partition is initialized with a public and private keys. This is necessary to
 * issue and sign tokens.</p>
 *
 * @author Pedro Igor
 */
@Startup
@Singleton
public class SecurityInitializer {

    public static final String KEYSTORE_FILE_PATH = "/keystore.jks";

    private KeyStore keyStore;

    public void initialize(@Observes PartitionManagerCreateEvent event) {
        PartitionManager partitionManager = event.getPartitionManager();

        createDefaultPartition(partitionManager);

        createUser("john", "john", ApplicationRole.USER, partitionManager);
        createUser("duke", "duke", ApplicationRole.MAINTAINER, partitionManager);
        createUser("admin", "admin", ApplicationRole.ADMIN, partitionManager);
    }

    private void createDefaultPartition(PartitionManager partitionManager) {
        Realm partition = partitionManager.getPartition(Realm.class, Realm.DEFAULT_REALM);

        if (partition == null) {
            try {
                partition = new Realm(Realm.DEFAULT_REALM);

                partition.setAttribute(new Attribute<byte[]>("PublicKey", getPublicKey()));
                partition.setAttribute(new Attribute<byte[]>("PrivateKey", getPrivateKey()));

                partitionManager.add(partition);
            } catch (Exception e) {
                throw new SecurityConfigurationException("Could not create default partition.", e);
            }
        }
    }

    private byte[] getPrivateKey() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return getKeyStore().getKey("servercert", "test123".toCharArray()).getEncoded();
    }

    private byte[] getPublicKey() throws KeyStoreException {
        return getKeyStore().getCertificate("servercert").getPublicKey().getEncoded();
    }

    private KeyStore getKeyStore() {
        if (this.keyStore == null) {
            try {
                this.keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                getKeyStore().load(getClass().getResourceAsStream(KEYSTORE_FILE_PATH), "store123".toCharArray());
            } catch (Exception e) {
                throw new SecurityException("Could not load key store.", e);
            }
        }

        return this.keyStore;
    }

    /**
     * Take in the username, password, and Role to create default users.
     * 
     * @param loginName
     * @param password
     * @param userRole
     */
    private void createUser(String loginName, String password, String userRole, PartitionManager partitionManager) {
        IdentityManager identityManager = partitionManager.createIdentityManager();

        // user already exists
        if (getUser(identityManager, loginName) != null) {
            return;
        }

        User user = new User(loginName);

        // let's store an user
        identityManager.add(user);

        Password credential = new Password(password);

        // let's update the password-based credential for this user
        identityManager.updateCredential(user, credential);

        Role role = getRole(identityManager, userRole);

        // role does not exists, let's create it
        if (role == null) {
            role = new Role(userRole);
            identityManager.add(role);
        }

        RelationshipManager relationshipManager = partitionManager.createRelationshipManager();

        // let's grant to the user the given role
        grantRole(relationshipManager, user, role);
    }

}
