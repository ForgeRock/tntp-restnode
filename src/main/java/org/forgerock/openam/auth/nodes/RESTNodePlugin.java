/*
 * This code is to be used exclusively in connection with ForgeRock’s software or services. 
 * ForgeRock only offers ForgeRock software or services to legal entities who have entered 
 * into a binding license agreement with ForgeRock. 
 */


package org.forgerock.openam.auth.nodes;

import org.forgerock.openam.auth.node.api.AbstractNodeAmPlugin;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.plugins.PluginException;
import org.forgerock.openam.sm.AnnotatedServiceRegistry;

import javax.inject.Inject;

import static java.util.Arrays.asList;


/**
 * Core nodes installed by default with no engine dependencies.
 */
public class RESTNodePlugin extends AbstractNodeAmPlugin {

    private final AnnotatedServiceRegistry serviceRegistry;
    static String currentVersion = "8.1.3";
    static final String logAppender = "[Version: " + currentVersion + "][Marketplace] ";

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
    public void upgrade(String fromVersion) throws PluginException {
        pluginTools.upgradeAuthNode(RESTNode.class);
        // Version 2 of the node was added in 8.1.0. Where it is already installed, its schema is replaced so that new
        // settings appear: installAuthNode, called by super.upgrade, skips a node that is already installed.
        if (inRange("8.1.0", fromVersion, currentVersion)) {
            pluginTools.upgradeAuthNode(RESTNodeV2.class);
        }
        super.upgrade(fromVersion);
    }

    @Override
    protected Iterable<? extends Class<? extends Node>> getNodes() {
        return asList(
                RESTNode.class,
                RESTNodeV2.class
        );
    }
}
