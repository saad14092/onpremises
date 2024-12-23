package com.structurizr.onpremises.web.workspace.management;

import com.structurizr.onpremises.component.search.SearchComponent;
import com.structurizr.onpremises.component.search.SearchComponentException;
import com.structurizr.onpremises.component.workspace.WorkspaceComponentException;
import com.structurizr.onpremises.component.workspace.WorkspaceMetaData;
import com.structurizr.onpremises.domain.User;
import com.structurizr.onpremises.configuration.Configuration;
import com.structurizr.onpremises.web.workspace.AbstractWorkspaceController;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class DeleteWorkspaceController extends AbstractWorkspaceController {

    private static final Log log = LogFactory.getLog(DeleteWorkspaceController.class);

    private SearchComponent searchComponent;

    @Autowired
    public void setSearchComponent(SearchComponent searchComponent) {
        this.searchComponent = searchComponent;
    }

    @RequestMapping(value="/workspace/{workspaceId}/delete", method = RequestMethod.POST)
    @PreAuthorize("isAuthenticated()")
    public String deleteWorkspace(@PathVariable("workspaceId")long workspaceId, ModelMap model) {
        Configuration configuration = Configuration.getInstance();
        User user = getUser();

        try {
            WorkspaceMetaData workspace = workspaceComponent.getWorkspaceMetaData(workspaceId);
            if (workspace != null) {
                if (configuration.getAdminUsersAndRoles().isEmpty() || user.isAdmin()) {
                    if (workspaceComponent.deleteWorkspace(workspaceId)) {
                        try {
                            searchComponent.delete(workspaceId);
                        } catch (SearchComponentException e) {
                            log.error(e);
                        }
                    }
                }
            } else {
                return show404Page(model);
            }
        } catch (WorkspaceComponentException e) {
            log.error(e);
        }

        return "redirect:/dashboard";
    }

}