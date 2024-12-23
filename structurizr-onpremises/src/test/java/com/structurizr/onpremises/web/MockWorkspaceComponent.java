package com.structurizr.onpremises.web;

import com.structurizr.onpremises.component.workspace.*;
import com.structurizr.onpremises.domain.Image;
import com.structurizr.onpremises.domain.User;
import com.structurizr.onpremises.domain.InputStreamAndContentLength;

import java.io.File;
import java.util.Collection;
import java.util.List;

public abstract class MockWorkspaceComponent implements WorkspaceComponent {

    @Override
    public Collection<WorkspaceMetaData> getWorkspaces() {
        return null;
    }

    @Override
    public Collection<WorkspaceMetaData> getWorkspaces(User user) throws WorkspaceComponentException {
        return null;
    }

    @Override
    public WorkspaceMetaData getWorkspaceMetaData(long workspaceId) {
        return null;
    }

    @Override
    public void putWorkspaceMetaData(WorkspaceMetaData workspaceMetaData) throws WorkspaceComponentException {

    }

    @Override
    public String getWorkspace(long workspaceId, String branch, String version) throws WorkspaceComponentException {
        return null;
    }

    @Override
    public long createWorkspace(User user) throws WorkspaceComponentException {
        return 0;
    }

    @Override
    public boolean deleteBranch(long workspaceId, String branch) throws WorkspaceComponentException {
        return false;
    }

    @Override
    public boolean deleteWorkspace(long workspaceId) throws WorkspaceComponentException {
        return false;
    }

    @Override
    public void putWorkspace(long workspaceId, String branch, String json) throws WorkspaceComponentException {

    }

    @Override
    public List<WorkspaceVersion> getWorkspaceVersions(long workspaceId, String branch) {
        return List.of();
    }

    @Override
    public List<WorkspaceBranch> getWorkspaceBranches(long workspaceId) throws WorkspaceComponentException {
        return List.of();
    }

    @Override
    public boolean lockWorkspace(long workspaceId, String username, String agent) {
        return false;
    }

    @Override
    public boolean unlockWorkspace(long workspaceId) {
        return false;
    }

    @Override
    public boolean putImage(long workspaceId, String filename, File file) throws WorkspaceComponentException {
        return false;
    }

    @Override
    public List<Image> getImages(long workspaceId) throws WorkspaceComponentException {
        return null;
    }

    @Override
    public InputStreamAndContentLength getImage(long workspaceId, String diagramKey) throws WorkspaceComponentException {
        return null;
    }

    @Override
    public boolean deleteImages(long workspaceId) throws WorkspaceComponentException {
        return false;
    }

    @Override
    public void makeWorkspacePublic(long workspaceId) throws WorkspaceComponentException {

    }

    @Override
    public void makeWorkspacePrivate(long workspaceId) throws WorkspaceComponentException {

    }

    @Override
    public void shareWorkspace(long workspaceId) throws WorkspaceComponentException {

    }

    @Override
    public void unshareWorkspace(long workspaceId) throws WorkspaceComponentException {

    }

}