package com.structurizr.onpremises.component.search;

import com.structurizr.Workspace;

import java.util.List;
import java.util.Set;

/**
 * Provides search facilities for workspaces.
 */
public interface SearchComponent {

    void start();

    void stop();

    boolean isEnabled();

    void index(Workspace workspace) throws SearchComponentException;

    List<SearchResult> search(String query, String type, Set<Long> workspaceIds) throws SearchComponentException;

    void delete(long workspaceId) throws SearchComponentException;

}