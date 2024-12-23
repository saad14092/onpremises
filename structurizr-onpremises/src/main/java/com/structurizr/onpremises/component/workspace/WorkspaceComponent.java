package com.structurizr.onpremises.component.workspace;

import com.structurizr.onpremises.domain.Image;
import com.structurizr.onpremises.domain.InputStreamAndContentLength;
import com.structurizr.onpremises.domain.User;

import java.io.File;
import java.util.Collection;
import java.util.List;

/**
 * Provides access to workspace data stored on the file system, Amazon Web Services S3, or Microsoft Azure Blob Storage.
 */
public interface WorkspaceComponent {

    Collection<WorkspaceMetaData> getWorkspaces() throws WorkspaceComponentException;

    Collection<WorkspaceMetaData> getWorkspaces(User user) throws WorkspaceComponentException;

    WorkspaceMetaData getWorkspaceMetaData(long workspaceId) throws WorkspaceComponentException;

    void putWorkspaceMetaData(WorkspaceMetaData workspaceMetaData) throws WorkspaceComponentException;

    String getWorkspace(long workspaceId, String branch, String version) throws WorkspaceComponentException;

    long createWorkspace(User user) throws WorkspaceComponentException;

    boolean deleteBranch(long workspaceId, String branch) throws WorkspaceComponentException;

    boolean deleteWorkspace(long workspaceId) throws WorkspaceComponentException;

    void putWorkspace(long workspaceId, String branch, String json) throws WorkspaceComponentException;

    List<WorkspaceVersion> getWorkspaceVersions(long workspaceId, String branch) throws WorkspaceComponentException;

    List<WorkspaceBranch> getWorkspaceBranches(long workspaceId) throws WorkspaceComponentException;

    boolean lockWorkspace(long workspaceId, String username, String agent) throws WorkspaceComponentException;

    boolean unlockWorkspace(long workspaceId) throws WorkspaceComponentException;

    boolean putImage(long workspaceId, String filename, File file) throws WorkspaceComponentException;

    List<Image> getImages(long workspaceId) throws WorkspaceComponentException;

    InputStreamAndContentLength getImage(long workspaceId, String diagramKey) throws WorkspaceComponentException;

    boolean deleteImages(long workspaceId) throws WorkspaceComponentException;

    void makeWorkspacePublic(long workspaceId) throws WorkspaceComponentException;

    void makeWorkspacePrivate(long workspaceId) throws WorkspaceComponentException;

    void shareWorkspace(long workspaceId) throws WorkspaceComponentException;

    void unshareWorkspace(long workspaceId) throws WorkspaceComponentException;

}