package com.structurizr.onpremises.util;

import com.structurizr.Workspace;
import com.structurizr.onpremises.configuration.Configuration;
import com.structurizr.onpremises.configuration.Features;
import com.structurizr.validation.WorkspaceScopeValidationException;
import com.structurizr.validation.WorkspaceScopeValidatorFactory;

public class WorkspaceValidationUtils {

    public static void validateWorkspaceScope(Workspace workspace) throws WorkspaceScopeValidationException {
        // if workspace scope validation is enabled, reject workspaces without a defined scope
        if (Configuration.getInstance().isFeatureEnabled(Features.WORKSPACE_SCOPE_VALIDATION)) {
            if (workspace.getConfiguration().getScope() == null) {
                throw new WorkspaceScopeValidationException("Strict workspace scope validation has been enabled for this on-premises installation. Unscoped workspaces are not permitted - see https://docs.structurizr.com/workspaces for more information.");
            }
        }

        // validate workspace scope
        WorkspaceScopeValidatorFactory.getValidator(workspace).validate(workspace);
    }

}
