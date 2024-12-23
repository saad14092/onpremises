package com.structurizr.onpremises.component.workspace;

import com.structurizr.AbstractWorkspace;
import com.structurizr.Workspace;
import com.structurizr.configuration.Role;
import com.structurizr.configuration.Visibility;
import com.structurizr.configuration.WorkspaceConfiguration;
import com.structurizr.configuration.WorkspaceScope;
import com.structurizr.encryption.AesEncryptionStrategy;
import com.structurizr.encryption.EncryptedWorkspace;
import com.structurizr.encryption.EncryptionLocation;
import com.structurizr.encryption.EncryptionStrategy;
import com.structurizr.io.json.EncryptedJsonReader;
import com.structurizr.io.json.EncryptedJsonWriter;
import com.structurizr.onpremises.configuration.Configuration;
import com.structurizr.onpremises.configuration.Features;
import com.structurizr.onpremises.configuration.StructurizrProperties;
import com.structurizr.onpremises.domain.Image;
import com.structurizr.onpremises.domain.InputStreamAndContentLength;
import com.structurizr.onpremises.domain.User;
import com.structurizr.onpremises.util.DateUtils;
import com.structurizr.onpremises.util.EarlyAccessFeaturesNotAvailableException;
import com.structurizr.onpremises.util.WorkspaceValidationUtils;
import com.structurizr.util.StringUtils;
import com.structurizr.util.WorkspaceUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static com.structurizr.onpremises.configuration.StructurizrProperties.*;

class WorkspaceComponentImpl implements WorkspaceComponent {

    private static final Log log = LogFactory.getLog(WorkspaceComponentImpl.class);
    private static final String ENCRYPTION_STRATEGY_STRING = "encryptionStrategy";
    private static final String CIPHERTEXT_STRING = "ciphertext";

    private final WorkspaceDao workspaceDao;
    private final String encryptionPassphrase;

    private WorkspaceMetadataCache workspaceMetadataCache;
    private ExecutorService executorService;

    WorkspaceComponentImpl() {
        String dataStorageImplementationName = Configuration.getInstance().getProperty(DATA_STORAGE_IMPLEMENTATION);

        if (StructurizrProperties.DATA_STORAGE_VARIANT_AMAZON_WEB_SERVICES_S3.equals(dataStorageImplementationName)) {
            this.workspaceDao = new AmazonWebServicesS3WorkspaceDao();
        } else if (StructurizrProperties.DATA_STORAGE_VARIANT_AZURE_BLOB_STORAGE.equals(dataStorageImplementationName)) {
            if (!Configuration.getInstance().earlyAccessFeaturesAvailable()) {
                throw new EarlyAccessFeaturesNotAvailableException("Microsoft Azure Blob Storage");
            }

            this.workspaceDao = new AzureBlobStorageWorkspaceDao();
        } else {
            this.workspaceDao = new FileSystemWorkspaceDao(Configuration.getInstance().getDataDirectory());
        }

        encryptionPassphrase = Configuration.getInstance().getProperty(StructurizrProperties.ENCRYPTION_PASSPHRASE);

        initCache();
        initThreadPool();
    }

    WorkspaceComponentImpl(WorkspaceDao workspaceDao, String encryptionPassphrase) {
        this.workspaceDao = workspaceDao;
        this.encryptionPassphrase = encryptionPassphrase;
        this.workspaceMetadataCache = new NoOpWorkspaceMetadataCache();
        this.executorService = Executors.newSingleThreadExecutor();
    }

    private void initCache() {
        String cacheImplementation = Configuration.getInstance().getProperty(CACHE_IMPLEMENTATION);

        if (cacheImplementation.equalsIgnoreCase(StructurizrProperties.CACHE_VARIANT_LOCAL)) {
            workspaceMetadataCache = new LocalWorkspaceMetadataCache();
        } else if (cacheImplementation.equalsIgnoreCase(StructurizrProperties.CACHE_VARIANT_REDIS)) {
            workspaceMetadataCache = new RedisWorkspaceMetadataCache();
        } else {
            workspaceMetadataCache = new NoOpWorkspaceMetadataCache();
        }
    }

    private void initThreadPool() {
        int threads = Integer.parseInt(Configuration.getInstance().getProperty(StructurizrProperties.WORKSPACE_THREADS));
         executorService = Executors.newFixedThreadPool(threads);
    }

    public void stop() {
        workspaceMetadataCache.stop();
        executorService.shutdownNow();
    }

    @Override
    public Collection<WorkspaceMetaData> getWorkspaces() throws WorkspaceComponentException {
        List<WorkspaceMetaData> workspaces = new ArrayList<>();
        Collection<Long> workspaceIds = workspaceDao.getWorkspaceIds();

        List<Future<WorkspaceMetaData>> futures = workspaceIds.stream()
                .map(workspaceId -> executorService.submit(() -> getWorkspaceMetaData(workspaceId)))
                .toList();

        for (Future<WorkspaceMetaData> future : futures) {
            try {
                WorkspaceMetaData workspace = future.get();
                if (workspace != null) {
                    workspaces.add(workspace);
                }
            } catch (InterruptedException | ExecutionException e) {
                throw new WorkspaceComponentException("Error fetching workspace metadata", e);
            }
        }

        workspaces.sort(Comparator.comparing(wmd -> wmd.getName().toLowerCase()));

        return workspaces;
    }

    @Override
    public Collection<WorkspaceMetaData> getWorkspaces(User user) throws WorkspaceComponentException {
        Collection<WorkspaceMetaData> workspaces = new ArrayList<>();

        try {
            workspaces = getWorkspaces();
        } catch (WorkspaceComponentException e) {
            log.error(e);
        }

        List<WorkspaceMetaData> filteredWorkspaces = new ArrayList<>();

        if (user == null) {
            // unauthenticated request
            for (WorkspaceMetaData workspace : workspaces) {
                if (workspace.isPublicWorkspace() || workspace.hasNoUsersConfigured()) {
                    // so anybody can see it
                    workspace.setUrlPrefix("/share");
                    filteredWorkspaces.add(workspace);
                }
            }
        } else {
            // authenticated request
            for (WorkspaceMetaData workspace : workspaces) {
                if (workspace.isWriteUser(user)) {
                    // the user has read-write access to the workspace
                    workspace.setUrlPrefix("/workspace");
                    filteredWorkspaces.add(workspace);
                } else if (workspace.isReadUser(user)) {
                    // the user has read-only access to the workspace
                    workspace.setUrlPrefix("/workspace");
                    filteredWorkspaces.add(workspace);
                } else if (workspace.hasNoUsersConfigured()) {
                    // the workspace has no users configured, so anybody can see it
                    workspace.setUrlPrefix("/workspace");
                    filteredWorkspaces.add(workspace);
                } else if (workspace.isPublicWorkspace()) {
                    // so anybody can see it
                    workspace.setUrlPrefix("/share");
                    filteredWorkspaces.add(workspace);
                }
            }
        }

        return filteredWorkspaces;
    }

    @Override
    public WorkspaceMetaData getWorkspaceMetaData(long workspaceId) throws WorkspaceComponentException {
        WorkspaceMetaData wmd = workspaceMetadataCache.get(workspaceId);

        if (wmd == null) {
            wmd = workspaceDao.getWorkspaceMetaData(workspaceId);
            if (wmd != null) {
                workspaceMetadataCache.put(wmd);
            }
        }

        if (wmd != null && wmd.isArchived()) {
            return null;
        }

        return wmd;
    }

    @Override
    public void putWorkspaceMetaData(WorkspaceMetaData workspaceMetaData) throws WorkspaceComponentException {
        workspaceDao.putWorkspaceMetaData(workspaceMetaData);

        if (workspaceMetaData != null) {
            workspaceMetadataCache.put(workspaceMetaData);
        }
    }

    @Override
    public String getWorkspace(long workspaceId, String branch, String version) throws WorkspaceComponentException {
        WorkspaceBranch.validateBranchName(branch);
        String json = workspaceDao.getWorkspace(workspaceId, branch, version);

        if (json == null) {
            if (!StringUtils.isNullOrEmpty(branch)) {
                // branch likely doesn't exist, so return the main branch instead
                json = workspaceDao.getWorkspace(workspaceId, WorkspaceBranch.NO_BRANCH, WorkspaceVersion.LATEST_VERSION);
            }
        }

        if (json == null) {
            if (!StringUtils.isNullOrEmpty(version)) {
                throw new WorkspaceComponentException("Could not get workspace " + workspaceId + " with version " + version);
            } else {
                throw new WorkspaceComponentException("Could not get workspace " + workspaceId);
            }
        }

        if (json.contains(ENCRYPTION_STRATEGY_STRING) && json.contains(CIPHERTEXT_STRING)) {
            EncryptedJsonReader encryptedJsonReader = new EncryptedJsonReader();
            StringReader stringReader = new StringReader(json);
            try {
                EncryptedWorkspace encryptedWorkspace = encryptedJsonReader.read(stringReader);

                if (encryptedWorkspace.getEncryptionStrategy().getLocation() == EncryptionLocation.Server) {
                    if (StringUtils.isNullOrEmpty(encryptionPassphrase)) {
                        log.warn("Workspace " + workspaceId + " seems to be encrypted, but a passphrase has not been set");
                    }

                    encryptedWorkspace.getEncryptionStrategy().setPassphrase(encryptionPassphrase);
                    json = encryptedWorkspace.getPlaintext();
                } else if (encryptedWorkspace.getEncryptionStrategy().getLocation() == EncryptionLocation.Client) {
                    // do nothing, we'll pass back the JSON as-is
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw new WorkspaceComponentException("Could not get workspace " + workspaceId, e);
            }
        } else {
            // again, do nothing, the JSON was stored unencrypted
        }

        return json;
    }

    @Override
    public long createWorkspace(User user) throws WorkspaceComponentException {
        try {
            long workspaceId = workspaceDao.createWorkspace(user);
            NumberFormat format = new DecimalFormat("0000");

            Workspace workspace = new Workspace("Workspace " + format.format(workspaceId), "Description");

            if (Configuration.getInstance().isFeatureEnabled(Features.WORKSPACE_SCOPE_VALIDATION)) {
                workspace.getConfiguration().setScope(WorkspaceScope.SoftwareSystem);
            }

            String json = WorkspaceUtils.toJson(workspace, false);

            putWorkspace(workspaceId, null, json);

            return workspaceId;
        } catch (Exception e) {
            throw new WorkspaceComponentException("Could not create workspace", e);
        }
    }

    @Override
    public boolean deleteBranch(long workspaceId, String branch) throws WorkspaceComponentException {
        return workspaceDao.deleteBranch(workspaceId, branch);
    }

    @Override
    public boolean deleteWorkspace(long workspaceId) throws WorkspaceComponentException {
        if (Configuration.getInstance().isFeatureEnabled(Features.WORKSPACE_ARCHIVING)) {
            log.debug("Archiving workspace with ID " + workspaceId);
            WorkspaceMetaData workspaceMetaData = getWorkspaceMetaData(workspaceId);
            workspaceMetaData.setArchived(true);
            putWorkspaceMetaData(workspaceMetaData);

            return true;
        } else {
            log.debug("Deleting workspace with ID " + workspaceId);
            return workspaceDao.deleteWorkspace(workspaceId);
        }
    }

    @Override
    public void putWorkspace(long workspaceId, String branch, String json) throws WorkspaceComponentException {
        WorkspaceBranch.validateBranchName(branch);

        try {
            AbstractWorkspace workspaceToBeStored;
            String jsonToBeStored;
            WorkspaceConfiguration configuration;

            WorkspaceMetaData workspaceMetaData = getWorkspaceMetaData(workspaceId);
            if (workspaceMetaData == null) {
                workspaceMetaData = new WorkspaceMetaData(workspaceId);
            }

            if (Configuration.getInstance().getWorkspaceEventListener() != null) {
                WorkspaceEvent event = createWorkspaceEvent(workspaceMetaData, json);
                Configuration.getInstance().getWorkspaceEventListener().beforeSave(event);
                json = event.getJson();
            }

            if (json.contains(ENCRYPTION_STRATEGY_STRING) && json.contains(CIPHERTEXT_STRING)) {
                EncryptedJsonReader jsonReader = new EncryptedJsonReader();
                StringReader stringReader = new StringReader(json);
                EncryptedWorkspace encryptedWorkspace = jsonReader.read(stringReader);

                encryptedWorkspace.setId(workspaceId);
                encryptedWorkspace.setLastModifiedDate(DateUtils.removeMilliseconds(DateUtils.getNow()));

                // also remove the workspace configuration
                configuration = encryptedWorkspace.getConfiguration();
                encryptedWorkspace.clearConfiguration();
                encryptedWorkspace.getConfiguration().setScope(configuration.getScope());

                // copy the last modified details from the workspace
                workspaceMetaData.setLastModifiedDate(encryptedWorkspace.getLastModifiedDate());
                workspaceMetaData.setLastModifiedAgent(encryptedWorkspace.getLastModifiedAgent());
                workspaceMetaData.setLastModifiedUser(encryptedWorkspace.getLastModifiedUser());

                // write it back as an encrypted workspace JSON
                EncryptedJsonWriter encryptedJsonWriter = new EncryptedJsonWriter(false);
                StringWriter stringWriter = new StringWriter();
                encryptedJsonWriter.write(encryptedWorkspace, stringWriter);

                workspaceMetaData.setClientSideEncrypted(true);
                workspaceToBeStored = encryptedWorkspace;
                jsonToBeStored = stringWriter.toString();
            } else {
                Workspace workspace = WorkspaceUtils.fromJson(json);

                WorkspaceValidationUtils.validateWorkspaceScope(workspace);

                workspace.setId(workspaceId);
                workspace.setLastModifiedDate(DateUtils.removeMilliseconds(DateUtils.getNow()));

                // also remove the configuration
                configuration = workspace.getConfiguration();
                workspace.clearConfiguration();
                workspace.getConfiguration().setScope(configuration.getScope());

                // copy the last modified details from the workspace
                workspaceMetaData.setLastModifiedDate(workspace.getLastModifiedDate());
                workspaceMetaData.setLastModifiedAgent(workspace.getLastModifiedAgent());
                workspaceMetaData.setLastModifiedUser(workspace.getLastModifiedUser());

                workspaceMetaData.setClientSideEncrypted(false);
                workspaceToBeStored = workspace;

                if (!StringUtils.isNullOrEmpty(encryptionPassphrase)) {
                    EncryptionStrategy encryptionStrategy = new AesEncryptionStrategy(128, 1000, encryptionPassphrase);
                    encryptionStrategy.setLocation(EncryptionLocation.Server);

                    EncryptedWorkspace encryptedWorkspace = new EncryptedWorkspace(workspace, json, encryptionStrategy);
                    encryptedWorkspace.setLastModifiedDate(workspace.getLastModifiedDate());

                    EncryptedJsonWriter encryptedJsonWriter = new EncryptedJsonWriter(false);
                    StringWriter stringWriter = new StringWriter();
                    encryptedJsonWriter.write(encryptedWorkspace, stringWriter);
                    jsonToBeStored = stringWriter.toString();
                } else {
                    jsonToBeStored = WorkspaceUtils.toJson(workspace, false);
                }
            }

            workspaceMetaData.setSize(jsonToBeStored.length());

            // check the workspace lock
            if (workspaceMetaData.isLocked() && !workspaceMetaData.isLockedBy(workspaceToBeStored.getLastModifiedUser(), workspaceToBeStored.getLastModifiedAgent())) {
                SimpleDateFormat sdf = new SimpleDateFormat(DateUtils.USER_FRIENDLY_DATE_FORMAT);
                throw new WorkspaceComponentException("The workspace could not be saved because the workspace was locked by " + workspaceMetaData.getLockedUser() + " at " + sdf.format(workspaceMetaData.getLockedDate()) + ".");
            }

            // use the DAO to write the workspace
            workspaceDao.putWorkspace(workspaceMetaData, jsonToBeStored, branch);

            if (StringUtils.isNullOrEmpty(branch)) {
                // only store workspace metadata for the main branch
                try {
                    workspaceMetaData.setName(workspaceToBeStored.getName());
                    workspaceMetaData.setDescription(workspaceToBeStored.getDescription());

                    // configure users
                    if (configuration != null) {
                        if (configuration.getVisibility() != null) {
                            workspaceMetaData.setPublicWorkspace(configuration.getVisibility() == Visibility.Public);
                        }

                        if (!configuration.getUsers().isEmpty()) {
                            workspaceMetaData.clearWriteUsers();
                            workspaceMetaData.clearReadUsers();

                            for (com.structurizr.configuration.User user : configuration.getUsers()) {
                                if (user.getRole() == Role.ReadWrite) {
                                    workspaceMetaData.addWriteUser(user.getUsername());
                                } else {
                                    workspaceMetaData.addReadUser(user.getUsername());
                                }
                            }
                        }
                    }

                    putWorkspaceMetaData(workspaceMetaData);
                } catch (Exception e) {
                    log.error(e);
                }
            }
        } catch (WorkspaceComponentException wce) {
            throw wce;
        } catch (Exception e) {
            e.printStackTrace();
            throw new WorkspaceComponentException(e.getMessage(), e);
        }
    }

    private WorkspaceEvent createWorkspaceEvent(WorkspaceMetaData workspaceMetaData, String workspaceAsJson) {
        return new WorkspaceEvent() {

            private String json = workspaceAsJson;

            @Override
            public WorkspaceProperties getWorkspaceProperties() {
                return workspaceMetaData.toWorkspaceProperties();
            }

            @Override
            public String getJson() {
                return json;
            }

            @Override
            public void setJson(String json) {
                this.json = json;
            }
        };
//
//            public WorkspaceProperties(WorkspaceMetaData workspaceMetaData) {
//            this.id = workspaceMetaData.getId();
//            this.name = workspaceMetaData.getName();
//            this.description = workspaceMetaData.getDescription();
//
//            this.users = new LinkedHashSet<>();
//            for (String user : workspaceMetaData.getReadUsers()) {
//                users.add(new com.structurizr.configuration.User(user, Role.ReadOnly));
//            }
//            for (String user : workspaceMetaData.getWriteUsers()) {
//                users.add(new com.structurizr.configuration.User(user, Role.ReadWrite));
//            }
//
//            if (workspaceMetaData.isPublicWorkspace()) {
//                this.visibility = Visibility.Public;
//            } else {
//                this.visibility = Visibility.Private;
//            }
//
//            this.lastModifiedDate = workspaceMetaData.getLastModifiedDate();
//        }
//
//        this.workspaceId = workspaceMetaData.getId();
//        this.workspaceProperties = new WorkspaceProperties(workspaceMetaData);
//        this.json = json;

    }

    @Override
    public List<WorkspaceVersion> getWorkspaceVersions(long workspaceId, String branch) throws WorkspaceComponentException {
        WorkspaceBranch.validateBranchName(branch);

        int maxVersions = Integer.parseInt(Configuration.getInstance().getProperty(StructurizrProperties.MAX_WORKSPACE_VERSIONS));
        List<WorkspaceVersion> versions = workspaceDao.getWorkspaceVersions(workspaceId, branch, maxVersions);
        versions.sort((v1, v2) -> v2.getLastModifiedDate().compareTo(v1.getLastModifiedDate()));

        if (versions.size() > maxVersions) {
            versions = versions.subList(0, maxVersions);
        }

        return versions;
    }

    @Override
    public List<WorkspaceBranch> getWorkspaceBranches(long workspaceId) throws WorkspaceComponentException {
        List<WorkspaceBranch> branches = new ArrayList<>();

        try {
            return workspaceDao.getWorkspaceBranches(workspaceId);
        } catch (Exception e) {
            log.error(e);
        }

        return branches;
    }

    @Override
    public boolean lockWorkspace(long workspaceId, String username, String agent) throws WorkspaceComponentException {
        WorkspaceMetaData workspaceMetaData = getWorkspaceMetaData(workspaceId);
        if (!workspaceMetaData.isLocked() || workspaceMetaData.isLockedBy(username, agent)) {
            workspaceMetaData.addLock(username, agent);

            try {
                putWorkspaceMetaData(workspaceMetaData);
                return true;
            } catch (WorkspaceComponentException e) {
                log.error(e);
            }
        }

        return false;
    }

    @Override
    public boolean unlockWorkspace(long workspaceId) throws WorkspaceComponentException {
        WorkspaceMetaData workspaceMetaData = getWorkspaceMetaData(workspaceId);
        workspaceMetaData.clearLock();

        try {
            putWorkspaceMetaData(workspaceMetaData);
            return true;
        } catch (WorkspaceComponentException e) {
            log.error(e);
        }

        return false;
    }

    @Override
    public void makeWorkspacePublic(long workspaceId) throws WorkspaceComponentException {
        WorkspaceMetaData workspace = getWorkspaceMetaData(workspaceId);
        workspace.setPublicWorkspace(true);
        putWorkspaceMetaData(workspace);
    }

    @Override
    public void makeWorkspacePrivate(long workspaceId) throws WorkspaceComponentException {
        WorkspaceMetaData workspace = getWorkspaceMetaData(workspaceId);
        workspace.setPublicWorkspace(false);
        putWorkspaceMetaData(workspace);
    }

    @Override
    public void shareWorkspace(long workspaceId) throws WorkspaceComponentException {
        WorkspaceMetaData workspace = getWorkspaceMetaData(workspaceId);
        workspace.setSharingToken(UUID.randomUUID().toString());
        putWorkspaceMetaData(workspace);
    }

    @Override
    public void unshareWorkspace(long workspaceId) throws WorkspaceComponentException {
        WorkspaceMetaData workspace = getWorkspaceMetaData(workspaceId);
        workspace.setSharingToken("");
        putWorkspaceMetaData(workspace);
    }

    @Override
    public boolean putImage(long workspaceId, String filename, File file) throws WorkspaceComponentException {
        return workspaceDao.putImage(workspaceId, filename, file);
    }

    @Override
    public List<Image> getImages(long workspaceId) throws WorkspaceComponentException {
        return workspaceDao.getImages(workspaceId);
    }

    @Override
    public InputStreamAndContentLength getImage(long workspaceId, String diagramKey) throws WorkspaceComponentException {
        return workspaceDao.getImage(workspaceId, diagramKey);
    }

    @Override
    public boolean deleteImages(long workspaceId) throws WorkspaceComponentException {
        return workspaceDao.deleteImages(workspaceId);
    }

}