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

CONTACTS.namespace("CONTACTS.security.currentUser");
CONTACTS.namespace("CONTACTS.security.loadCurrentUser");
CONTACTS.namespace("CONTACTS.security.restSecurityEndpoint");

// Set this to undefined so that when the user is not logged in system doesn't think they are. This is referenced in 
// app.js (#contacts-list-page -> pagebeforeshow)
CONTACTS.security.currentUser = undefined;

// Set this variable for all Security REST APIs base URL.
CONTACTS.security.restSecurityEndpoint = "rest/private/security/";

var securityService;

/**
 * The regural jQuery AJAX functions go here.  We do all the jQuery Mobile security work in the section above this.
 * 
 * @author Pedro Igor, Joshua Wilson
 */
$(document).ready(function() {
    //Initialize the vars in the beginning so that you will always have access to them.
    var getCurrentTime = CONTACTS.util.getCurrentTime,
        restSecurityEndpoint = CONTACTS.security.restSecurityEndpoint;

    var keycloak = Keycloak('keycloak.json');

    var updateToken = function (callback) {
        keycloak.updateToken(10)
            .success(function() {
                if (keycloak.idToken) {
                    console.log("[INFO] Updating token.");
                    securityService.endSession();
                    securityService.initSession(keycloak.token);
                    console.log("[INFO] Token updated.");

                    if (callback) {
                        callback();
                    }
                }
            })
            .error(function() {
                console.log("Error from KeyCloak.");
            });
    }

    keycloak.init({ onLoad: 'login-required' }).success(updateToken(function() {}));

    /**
     * Register a handler to be called when Ajax requests complete with an error. Whenever an Ajax request completes
     * with an error, jQuery triggers the ajaxError event. Any and all handlers that have been registered with the
     * .ajaxError() method are executed at this time. Note: This handler is not called for cross-domain script and
     * cross-domain JSONP requests. - from the jQuery docs
     *
     * This will be overridden by any ajax call that handles these errors it's self.
     */
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            securityService.secureRequest(xhr);
        },
        error: function( jqXHR, errorThrown ) {
            if (jqXHR.status == 400) {
                console.log("[ERROR] Bad request response from the server.");
            } else if (jqXHR.status == 403) {
                // Authorization denied. (Does not have permissions)
                console.log(getCurrentTime() + " [js/security.js] (document.ajaxError) - error in ajax" +
                    " - jqXHR = " + jqXHR.status +
                    ", errorThrown = " + errorThrown);
            } else if (jqXHR.status == 500) {
                console.log("[ERROR] Internal server error.");
            } else {
                console.log("[ERROR] Unexpected error from server.");
            }
        }
    });

    $.ajaxPrefilter(function( opts, originalOptions, jqXHR ) {
        // you could pass this option in on a "retry" so that it doesn't
        // get all recursive on you.
        if ( opts.retryAttempt ) {
            console.log("Not filtering retry request.");
            return;
        }

        var dfd = $.Deferred();

        // if the request works, return normally
        jqXHR.done(dfd.resolve);

        // if the request fails, do something else
        // yet still resolve
        jqXHR.fail(function() {
            if ( jqXHR.status === 401 ) {
                originalOptions.retryAttempt = true;
                updateToken(function() {
                    console.log("[INFO] Retrying previous request.");
                    $.ajax(originalOptions).then(dfd.resolve, dfd.reject);
                });
            } else {
                dfd.rejectWith( this, arguments );
            }
        });

        // NOW override the jqXHR's promise functions with our deferred
        return dfd.promise(jqXHR);
    });

    // Log out when the 'Log out' button is clicked.
    $(".security-logout-btn").click(function(e) {
        console.log(getCurrentTime() + " [js/security.js] (#security-logout-btn -> click) - start");
        
        var jqxhr = $.ajax({
            url: restSecurityEndpoint + "logout",
            type: "POST"
        }).done(function(data, textStatus, jqXHR) {
            console.log(getCurrentTime() + " [js/security.js] (#security-logout-btn -> click) - Successfully logged out");
            alert('Not implemented.')
        });
        
        console.log(getCurrentTime() + " [js/security.js] (#security-logout-btn -> click) - end");
    });
    
    //Initialize all the AJAX form events.
    var initSecurity = function () {
        console.log(getCurrentTime() + " [js/security.js] (initSecurity) - start");
        //Fetches the initial member data
        securityService = new SecurityService();
        console.log(getCurrentTime() + " [js/security.js] (initSecurity) - end");
    };

    /**
     * Attempts to load information about the current user.
     * 
     * This is called by CONTACTS.security.submitSignIn()
     */
    CONTACTS.security.loadCurrentUser = function() {
        console.log(getCurrentTime() + " [js/security.js] (loadCurrentUser) - start");
        
        // The server knows which user is logged in for the session and will return that.
        var jqxhr = $.ajax({
            url: restSecurityEndpoint + "user/info",
            contentType: "application/json",
            dataType: "json",
            type: "GET",
            async: false
        }).done(function(data, textStatus, jqXHR) {
            console.log(getCurrentTime() + " [js/security.js] (loadCurrentUser) - ajax done");
            
            // Store the logged in user credentials for Role access. 
            CONTACTS.security.currentUser = data;
            
        }).fail(function(jqXHR, textStatus, errorThrown) {
            
            // If something goes wrong set the currentUser to undefined.
            CONTACTS.security.currentUser = undefined;
            
            console.log(getCurrentTime() + " [js/security.js] (loadCurrentUser) - error in ajax" +
                    " - jqXHR = " + jqXHR.status +
                    ", textStatus = " + textStatus +
                    ", errorThrown = " + errorThrown +
                    ", responseText = " + jqXHR.responseText);
        });
        console.log(getCurrentTime() + " [js/security.js] (loadCurrentUser) - end");
    };

    var SecurityService = function() {
        this.initSession = function(token) {
            console.log("[INFO] Initializing user session.");
            console.log("[INFO] Token is :" + token);
            console.log("[INFO] Token Stored in session storage.");
            // persist token, user id to the storage
            sessionStorage.setItem('token', token);
        };

        this.endSession = function() {
            console.log("[INFO] Ending User Session.");
            sessionStorage.removeItem('token');
            console.log("[INFO] Token removed from session storage.");
        };

        this.getToken = function() {
            return sessionStorage.getItem('token');
        };

        this.secureRequest = function(requestConfig) {
            var token = this.getToken();

            if(token != null && token != '' && token != 'undefined') {
                console.log("[INFO] Securing request.");
                console.log("[INFO] Setting x-session-token header: " + token);
                requestConfig.setRequestHeader('Authorization',' Token ' + token);
            }
        };
    };

    initSecurity();
});
