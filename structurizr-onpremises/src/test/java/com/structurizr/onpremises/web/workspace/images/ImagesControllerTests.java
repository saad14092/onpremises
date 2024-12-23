package com.structurizr.onpremises.web.workspace.images;

import com.structurizr.onpremises.component.workspace.WorkspaceComponentException;
import com.structurizr.onpremises.component.workspace.WorkspaceMetaData;
import com.structurizr.onpremises.domain.Image;
import com.structurizr.onpremises.configuration.Configuration;
import com.structurizr.onpremises.web.ControllerTestsBase;
import com.structurizr.onpremises.web.MockWorkspaceComponent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ui.ModelMap;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ImagesControllerTests extends ControllerTestsBase {

    private ImagesController controller;
    private ModelMap model;

    @BeforeEach
    public void setUp() {
        controller = new ImagesController();
        model = new ModelMap();
        Configuration.init();
        clearUser();
    }

    @Test
    public void showAuthenticatedImages_ReturnsThe404Page_WhenTheWorkspaceDoesNotExist() {
        controller.setWorkspaceComponent(new MockWorkspaceComponent() {
            @Override
            public WorkspaceMetaData getWorkspaceMetaData(long workspaceId) {
                return null;
            }
        });

        setUser("user@example.com");
        String view = controller.showAuthenticatedImages(1, model);
        assertEquals("404", view);
    }

    @Test
    public void showAuthenticatedImages_ReturnsThe404Page_WhenTheUserDoesNotHaveAccess() {
        final WorkspaceMetaData workspaceMetaData = new WorkspaceMetaData(1);
        workspaceMetaData.addWriteUser("user2@example.com");
        controller.setWorkspaceComponent(new MockWorkspaceComponent() {
            @Override
            public WorkspaceMetaData getWorkspaceMetaData(long workspaceId) {
                return workspaceMetaData;
            }

            @Override
            public String getWorkspace(long workspaceId, String branch, String version) throws WorkspaceComponentException {
                return "json";
            }
        });

        setUser("user1@example.com");
        String view = controller.showAuthenticatedImages(1, model);
        assertEquals("404", view);
    }

    @Test
    public void showAuthenticatedImages_ReturnsTheWorkspaceSettingsPage_WhenTheWorkspaceHasNoUsersConfigured()  {
        final WorkspaceMetaData workspaceMetaData = new WorkspaceMetaData(1);
        controller.setWorkspaceComponent(new MockWorkspaceComponent() {
            @Override
            public WorkspaceMetaData getWorkspaceMetaData(long workspaceId) {
                return workspaceMetaData;
            }

            @Override
            public List<Image> getImages(long workspaceId) throws WorkspaceComponentException {
                List<Image> images = new ArrayList<>();
                images.add(new Image("name", 123456, new Date()));

                return images;
            }
        });

        setUser("user@example.com");
        String view = controller.showAuthenticatedImages(1, model);
        assertEquals("images", view);
        assertSame(workspaceMetaData, model.getAttribute("workspace"));
        assertTrue(workspaceMetaData.isEditable());
        List<Image> images = (List<Image>)model.getAttribute("images");
        assertEquals("name", images.get(0).getName());
        assertEquals("/workspace/1", model.getAttribute("urlPrefix"));
    }

    @Test
    public void showAuthenticatedImages_ReturnsTheWorkspaceSettingsPage_WhenTheUserHasWriteAccess()  {
        final WorkspaceMetaData workspaceMetaData = new WorkspaceMetaData(1);
        workspaceMetaData.addWriteUser("user1@example.com");
        controller.setWorkspaceComponent(new MockWorkspaceComponent() {
            @Override
            public WorkspaceMetaData getWorkspaceMetaData(long workspaceId) {
                return workspaceMetaData;
            }

            @Override
            public List<Image> getImages(long workspaceId) throws WorkspaceComponentException {
                List<Image> images = new ArrayList<>();
                images.add(new Image("name", 123456, new Date()));

                return images;
            }
        });

        setUser("user1@example.com");
        String view = controller.showAuthenticatedImages(1, model);
        assertEquals("images", view);
        assertSame(workspaceMetaData, model.getAttribute("workspace"));
        assertTrue(workspaceMetaData.isEditable());
        List<Image> images = (List<Image>)model.getAttribute("images");
        assertEquals("name", images.get(0).getName());
        assertEquals("/workspace/1", model.getAttribute("urlPrefix"));
    }

    @Test
    public void showAuthenticatedImages_ReturnsAnErrorPage_WhenTheUserHasReadAccess()  {
        final WorkspaceMetaData workspaceMetaData = new WorkspaceMetaData(1);
        workspaceMetaData.addReadUser("user1@example.com");
        controller.setWorkspaceComponent(new MockWorkspaceComponent() {
            @Override
            public WorkspaceMetaData getWorkspaceMetaData(long workspaceId) {
                return workspaceMetaData;
            }

            @Override
            public String getWorkspace(long workspaceId, String branch, String version) throws WorkspaceComponentException {
                return "json";
            }

            @Override
            public List<Image> getImages(long workspaceId) throws WorkspaceComponentException {
                List<Image> images = new ArrayList<>();
                images.add(new Image("name", 123456, new Date()));

                return images;
            }
        });

        setUser("user1@example.com");
        String view = controller.showAuthenticatedImages(1, model);
        assertEquals("images", view);
        assertSame(workspaceMetaData, model.getAttribute("workspace"));
        assertFalse(workspaceMetaData.isEditable());
        List<Image> images = (List<Image>)model.getAttribute("images");
        assertEquals("name", images.get(0).getName());
        assertEquals("/workspace/1", model.getAttribute("urlPrefix"));
    }

}