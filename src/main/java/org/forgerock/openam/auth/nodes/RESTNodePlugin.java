/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2023 ForgeRock AS.
 */
/*
 * jon.knight@forgerock.com
 *
 * Needed to register the node
 */

package org.forgerock.openam.auth.nodes;

import static java.util.Arrays.asList;

import javax.inject.Inject;

import org.forgerock.openam.auth.node.api.AbstractNodeAmPlugin;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.plugins.PluginException;
import org.forgerock.openam.sm.AnnotatedServiceRegistry;

import com.iplanet.sso.SSOException;
import com.sun.identity.sm.SMSException;

/**
 * Core nodes installed by default with no engine dependencies.
 */
public class RESTNodePlugin extends AbstractNodeAmPlugin {

    private final AnnotatedServiceRegistry serviceRegistry;
    static String currentVersion = "1.0.0";
    static final String logAppender = "[Version: " + currentVersion + "][Marketplace]";

    /**
     * DI-enabled constructor.
     * @param serviceRegistry A service registry instance.
     */
    @Inject
    public RESTNodePlugin(AnnotatedServiceRegistry serviceRegistry) {
        this.serviceRegistry = serviceRegistry;
    }

    @Override
    public String getPluginVersion() {
        return currentVersion;
    }

    @Override
    public void onStartup() throws PluginException {
        for (Class<? extends Node> nodeClass : getNodes()) {
            pluginTools.registerAuthNode(nodeClass);
        }
    }

    @Override
    protected Iterable<? extends Class<? extends Node>> getNodes() {
        return asList(
                RESTNode.class
        );
    }
}
