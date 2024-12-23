package com.structurizr.onpremises.component.review;

import com.structurizr.onpremises.domain.InputStreamAndContentLength;
import com.structurizr.onpremises.domain.review.Review;
import com.structurizr.onpremises.domain.review.Session;
import com.structurizr.onpremises.configuration.Configuration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

class FileSystemReviewDao implements ReviewDao {

    private static final Log log = LogFactory.getLog(FileSystemReviewDao.class);

    private static final String REVIEWS_DIRECTORY_NAME = "reviews";
    private static final String REVIEW_JSON_FILENAME = "review.json";
    private static final Pattern REVIEW_ID_PATTERN = Pattern.compile("[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}");

    FileSystemReviewDao() {
    }

    @Override
    public Set<String> getReviewIds() {
        File reviewsDirectory = getReviewsDirectory();
        File[] files = reviewsDirectory.listFiles(file -> file.isDirectory() && REVIEW_ID_PATTERN.matcher(file.getName()).matches());
        if (files != null) {
            return Arrays.stream(files).map(File::getName).collect(Collectors.toSet());
        } else {
            return Collections.emptySet();
        }
    }

    public void putReview(Review review) throws ReviewComponentException {
        try {
            File file = new File(getReviewDirectory(review.getId()), REVIEW_JSON_FILENAME);

            String json = Review.toJson(review);
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(bytes);
            fos.flush();
            fos.close();
        } catch (Exception e) {
            log.error(e);
            throw new ReviewComponentException("Could not create review");
        }
    }

    public Review getReview(String reviewId) throws ReviewComponentException {
        try {
            File file = new File(getReviewDirectory(reviewId), REVIEW_JSON_FILENAME);
            String json = new String(Files.readAllBytes(file.toPath()));
            Review review = Review.fromJson(json);

            if (review.getDateCreated() == null) {
                review.setDateCreated(new Date(file.lastModified()));
            }

            return review;
        } catch (Throwable t) {
            return null;
        }
    }

    public void submitReview(String reviewId, Session reviewSession) throws ReviewComponentException {
        try {
            File file = new File(getReviewDirectory(reviewId), "comments-" + new Date().getTime() + ".json");
            String json = Session.toJson(reviewSession);
            Files.writeString(file.toPath(), json);
        } catch (Exception e) {
            log.error(e);
            throw new ReviewComponentException("Could not submit review");
        }
    }

    public Collection<Session> getReviewSessions(String reviewId) throws ReviewComponentException {
        Collection<Session> reviewSessions = new ArrayList<>();

        File directory = getReviewDirectory(reviewId);
        File[] files = directory.listFiles((dir, name) -> name.startsWith("comments-") && name.endsWith(".json"));

        if (files != null) {
            for (File file : files) {
                try {
                    String json = Files.readString(file.toPath());
                    reviewSessions.add(Session.fromJson(json));
                } catch (Exception e) {
                    log.error(e);
                }
            }
        }

        return reviewSessions;
    }

    public void putDiagram(String reviewId, String filename, byte[] bytes) throws ReviewComponentException {
        try {
            File file = new File(getReviewDirectory(reviewId), filename);
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(bytes);
            fos.flush();
            fos.close();
        } catch (IOException e) {
            log.error(e);
        }
    }

    public boolean reviewExists(String reviewId) {
        return new File(getReviewDirectory(reviewId), REVIEW_JSON_FILENAME).exists();
    }

    public InputStreamAndContentLength getDiagram(String reviewId, String filename) throws ReviewComponentException {
        try {
            File file = new File(getReviewDirectory(reviewId), filename);
            if (file.exists()) {
                return new InputStreamAndContentLength(new FileInputStream(file), file.length());
            }
        } catch (FileNotFoundException e) {
            log.error(e);
        }

        return null;
    }

    private File getReviewsDirectory() {
        return new File(Configuration.getInstance().getDataDirectory(), REVIEWS_DIRECTORY_NAME);
    }

    private File getReviewDirectory(String reviewId) {
        File directory = new File(getReviewsDirectory(), reviewId);
        directory.mkdirs();

        return directory;
    }

}