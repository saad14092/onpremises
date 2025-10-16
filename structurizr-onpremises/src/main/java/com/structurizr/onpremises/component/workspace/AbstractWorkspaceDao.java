package com.structurizr.onpremises.component.workspace;

import com.structurizr.onpremises.configuration.StructurizrProperties;
import com.structurizr.onpremises.domain.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

abstract class AbstractWorkspaceDao implements WorkspaceDao {

    private static final Log log = LogFactory.getLog(WorkspaceDao.class);

    @Override
    public final long createWorkspace(User user, Long forcedWorkspaceId) throws WorkspaceComponentException {
        try {
            long workspaceId;
            if (forcedWorkspaceId != null) {
                workspaceId = forcedWorkspaceId;
            } else {
                List<Long> workspaceIds = getWorkspaceIds();
                if (workspaceIds.size() == 0) {
                    workspaceId = 1;
                } else {
                    Collections.sort(workspaceIds);
                    workspaceId = workspaceIds.get(workspaceIds.size()-1) + 1;
                }
            }

            try {
                // create and write the workspace metadata
                WorkspaceMetaData workspaceMetaData = new WorkspaceMetaData(workspaceId);
                if (user != null) {
                    workspaceMetaData.setOwner(user.getUsername());
                }
                workspaceMetaData.setApiKey(UUID.randomUUID().toString());
                workspaceMetaData.setApiSecret(UUID.randomUUID().toString());

                //Set/Reset read and write roles
                String globalReadRole = com.structurizr.onpremises.configuration.Configuration
                        .getInstance().getProperty(StructurizrProperties.GLOBAL_READ_ROLE);
                String globalWriteRole = com.structurizr.onpremises.configuration.Configuration
                        .getInstance().getProperty(StructurizrProperties.GLOBAL_WRITE_ROLE);
                //WARNING : clientId can be null !
                String clientId = com.structurizr.onpremises.configuration.Configuration
                        .getInstance().getProperty(StructurizrProperties.OIDC_CLIENT_CLIENT_ID);
                String wsId = String.valueOf(workspaceId);

                workspaceMetaData.clearReadUsers();
                workspaceMetaData.addReadUser(globalReadRole);
                workspaceMetaData.clearWriteUsers();
                workspaceMetaData.addWriteUser(globalWriteRole);

                if (clientId != null) {
                    String wsReadRole = com.structurizr.onpremises.configuration.Configuration
                            .getInstance().getProperty(StructurizrProperties.WORKSPACE_READ_ROLE_TEMPLATE)
                            .replace("$CLIENT_ID", clientId)
                            .replace("$WORKSPACE_ID", wsId);
                    String wsWriteRole = com.structurizr.onpremises.configuration.Configuration
                            .getInstance().getProperty(StructurizrProperties.WORKSPACE_WRITE_ROLE_TEMPLATE)
                            .replace("$CLIENT_ID", clientId)
                            .replace("$WORKSPACE_ID", wsId);
                    workspaceMetaData.addReadUser(wsReadRole);
                    workspaceMetaData.addWriteUser(wsWriteRole);
                }

                putWorkspaceMetaData(workspaceMetaData);
            } catch (Exception e) {
                log.error("Error while creating workspace: ", e);
            }

            return workspaceId;
        } catch (Exception e) {
            throw new WorkspaceComponentException("Could not create workspace", e);
        }
    }

}