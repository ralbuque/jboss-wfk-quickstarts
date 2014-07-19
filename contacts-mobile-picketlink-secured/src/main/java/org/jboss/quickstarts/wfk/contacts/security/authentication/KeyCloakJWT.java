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

import org.picketlink.json.jwt.JWT;

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * @author Pedro Igor
 */
public class KeyCloakJWT extends JWT {

    /**
     * <p> Creates a new instance using the claims set and values from the given {@link javax.json.JsonObject}. </p>
     *
     * @param headers
     * @param claims The claims set and their respective values.
     */
    protected KeyCloakJWT(JsonObject headers, JsonObject claims) {
        super(headers, claims);
    }

    public List<String> getRoles() {
        List<String> roles = new ArrayList<String>();
        JsonObject resourceAccess = getClaims().getJsonObject("resource_access");
        Collection<JsonValue> resources = resourceAccess.values();
        Iterator<JsonValue> resourcesIterator = resources.iterator();

        while (resourcesIterator.hasNext()) {
            JsonObject resource = (JsonObject) resourcesIterator.next();
            JsonArray rolesArray = resource.getJsonArray("roles");
            Iterator<JsonValue> rolesIterator = rolesArray.iterator();

            while (rolesIterator.hasNext()) {
                JsonString role = (JsonString) rolesIterator.next();

                roles.add(role.getString());
            }
        }

        return Collections.unmodifiableList(roles);
    }

    public String getUserName() {
        return getClaim("preferred_username");
    }
}
