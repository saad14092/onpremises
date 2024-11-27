package com.structurizr.onpremises.web.workspace.diagrams;

import com.structurizr.onpremises.component.workspace.WorkspaceMetaData;
import com.structurizr.onpremises.util.HtmlUtils;
import com.structurizr.onpremises.util.JsonUtils;
import com.structurizr.onpremises.web.workspace.AbstractWorkspaceController;
import com.structurizr.util.StringUtils;
import com.structurizr.view.PaperSize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Date;

@Controller
public class EmbedController extends AbstractWorkspaceController {

    @Override
    protected void addXFrameOptionsHeader(HttpServletRequest request, HttpServletResponse response) {
        // do nothing ... this page is supposed to be iframe'd
    }

    @RequestMapping(value = "/embed/{workspaceId}")
    public String embedDiagrams(
            @PathVariable("workspaceId") long workspaceId,
            @RequestParam(value = "diagram", required = false) String diagramIdentifier,
            @RequestParam(value = "apiKey", required = false) String apiKey,
            @RequestParam(required = false) boolean diagramSelector,
            @RequestParam(required = false, defaultValue = "") String iframe,
            @RequestParam(required = false) boolean health,
            @RequestParam(required = false) String perspective,
            ModelMap model) {

        WorkspaceMetaData workspace = workspaceComponent.getWorkspaceMetaData(workspaceId);
        if (workspace == null) {
            return "404";
        }

        if (workspace.isOpen()) {
            model.addAttribute("urlPrefix", "/share/" + workspaceId);
            return showEmbed(workspaceId, diagramIdentifier, diagramSelector, iframe, health, perspective, model);
        }

        if (!StringUtils.isNullOrEmpty(apiKey) && apiKey.equals(workspace.getApiKey())) {
            model.addAttribute("urlPrefix", "/workspace/" + workspaceId);
            return showEmbed(workspaceId, diagramIdentifier, diagramSelector, iframe, health, perspective, model);
        }

        return "404";
    }

    @RequestMapping(value = "/preview", method = RequestMethod.POST)
    public String previewDiagrams(ModelMap model,
            @RequestParam String source,
            @RequestParam(value = "diagram", required = false) String diagramIdentifier,
            @RequestParam(required = false) boolean diagramSelector,
            @RequestParam(required = false, defaultValue = "") String iframe) {

        return showPreview(source, diagramIdentifier, diagramSelector, iframe, model);
    }

    @RequestMapping(value = "/embed/{workspaceId}/{token}", method = RequestMethod.GET)
    public String embedDiagramsViaSharingToken(
            @PathVariable("workspaceId") long workspaceId,
            @PathVariable("token") String token,
            @RequestParam(value = "diagram", required = false) String diagramIdentifier,
            @RequestParam(required = false) boolean diagramSelector,
            @RequestParam(required = false, defaultValue = "") String iframe,
            @RequestParam(required = false) boolean health,
            @RequestParam(required = false) String perspective,
            ModelMap model) {

        WorkspaceMetaData workspace = workspaceComponent.getWorkspaceMetaData(workspaceId);
        if (workspace == null) {
            return show404Page(model);
        }

        if (workspace.isShareable() && workspace.getSharingToken().equals(token)) {
            model.addAttribute("urlPrefix", "/share/" + workspaceId + "/" + workspace.getSharingToken());
            return showEmbed(workspaceId, diagramIdentifier, diagramSelector, iframe, health, perspective, model);
        }

        return "404";
    }

    private String showPreview(
            String encodedWorkspaceAsJson,
            String diagramIdentifier,
            boolean diagramSelector,
            String iframe,
            ModelMap model) {

        diagramIdentifier = HtmlUtils.filterHtml(diagramIdentifier);
        diagramIdentifier = HtmlUtils.escapeQuoteCharacters(diagramIdentifier);
        iframe = HtmlUtils.filterHtml(iframe);

        WorkspaceMetaData workspace = new WorkspaceMetaData(0);
        workspace.setName("Workspace");
        workspace.setEditable(true);
        workspace.setLastModifiedDate(new Date());

        if (!StringUtils.isNullOrEmpty(diagramIdentifier)) {
            model.addAttribute("diagramIdentifier", diagramIdentifier);
        }

        addCommonAttributes(model, "", false);

        workspace.setEditable(false);
        model.addAttribute("workspace", workspace);
        model.addAttribute("workspaceAsJson", encodedWorkspaceAsJson);
        model.addAttribute("showToolbar", diagramSelector);
        model.addAttribute("showDiagramSelector", diagramSelector);
        model.addAttribute("embed", true);
        model.addAttribute("iframe", iframe);
        model.addAttribute("publishThumbnails", false);

        return "diagrams";
    }

    private String showEmbed(
            long workspaceId,
            String diagramIdentifier,
            boolean diagramSelector,
            String iframe,
            boolean health,
            String perspective,
            ModelMap model) {

        diagramIdentifier = HtmlUtils.filterHtml(diagramIdentifier);
        diagramIdentifier = HtmlUtils.escapeQuoteCharacters(diagramIdentifier);
        iframe = HtmlUtils.filterHtml(iframe);
        perspective = HtmlUtils.filterHtml(perspective);

        WorkspaceMetaData workspace = workspaceComponent.getWorkspaceMetaData(workspaceId);
        if (workspace == null) {
            return "404";
        }

        if (diagramIdentifier != null && diagramIdentifier.length() > 0) {
            model.addAttribute("diagramIdentifier", diagramIdentifier);
        }

        addCommonAttributes(model, "", false);

        workspace.setEditable(false);
        model.addAttribute("workspace", workspace);

        String json = workspaceComponent.getWorkspace(workspaceId, null, null);
        model.addAttribute("workspaceAsJson", JsonUtils.base64(json));
        model.addAttribute("showToolbar", diagramSelector);
        model.addAttribute("showDiagramSelector", diagramSelector);
        model.addAttribute("embed", true);
        model.addAttribute("iframe", iframe);
        model.addAttribute("health", health);
        model.addAttribute("perspective", perspective);
        model.addAttribute("publishThumbnails", false);

        return "diagrams";
    }

    @RequestMapping(value = "/embed", method = RequestMethod.GET)
    public String embedFromParent(@RequestParam(required = false, defaultValue = "0") long workspace,
                                  @RequestParam(required = false) String branch,
                                  @RequestParam(required = false) String version,
                                  @RequestParam(required = false) String type,
                                  @RequestParam(required = false) String view,
                                  @RequestParam(required = false) String perspective,
                                  @RequestParam(required = false, defaultValue = "false") boolean editable,
                                  @RequestParam(required = false, defaultValue = "") String iframe,
                                  @RequestParam(required = false) String urlPrefix,
                                  ModelMap model) {

        type = HtmlUtils.filterHtml(type);
        view = HtmlUtils.filterHtml(view);
        view = HtmlUtils.escapeQuoteCharacters(view);
        perspective = HtmlUtils.filterHtml(perspective);
        iframe = HtmlUtils.filterHtml(iframe);
        urlPrefix = HtmlUtils.filterHtml(urlPrefix);

        WorkspaceMetaData workspaceMetaData = new WorkspaceMetaData(workspace);
        workspaceMetaData.setName("Embedded workspace");
        workspaceMetaData.setEditable(editable);

        model.addAttribute("workspace", workspaceMetaData);
        model.addAttribute("loadWorkspaceFromParent", true);
        model.addAttribute("embed", true);
        model.addAttribute("iframe", iframe);
        addCommonAttributes(model, "", false);

        if (!StringUtils.isNullOrEmpty(urlPrefix)) {
            model.addAttribute("urlPrefix", urlPrefix);
        }

        addUrlSuffix(branch, version, model);

        if ("graph".equals(type)) {
            model.addAttribute("view", view);

            return "graph";
        } else if ("tree".equals(type)) {
            model.addAttribute("view", view);

            return "tree";
        } else {
            if (!StringUtils.isNullOrEmpty(view)) {
                model.addAttribute("diagramIdentifier", view);
            }

            if (!StringUtils.isNullOrEmpty(urlPrefix) && urlPrefix.startsWith("/workspace")) {
                model.addAttribute("publishThumbnails", StringUtils.isNullOrEmpty(branch) && StringUtils.isNullOrEmpty(version));
            } else {
                model.addAttribute("publishThumbnails", false);
            }

            if (workspaceMetaData.isEditable()) {
                model.addAttribute("paperSizes", PaperSize.getOrderedPaperSizes());
            }

            model.addAttribute("showToolbar", editable);
            model.addAttribute("showDiagramSelector", false);
            model.addAttribute("perspective", perspective);

            return "diagrams";
        }
    }

}