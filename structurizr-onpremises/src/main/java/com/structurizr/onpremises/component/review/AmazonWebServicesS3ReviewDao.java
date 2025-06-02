package com.structurizr.onpremises.component.review;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.*;
import com.structurizr.onpremises.configuration.Configuration;
import com.structurizr.onpremises.domain.InputStreamAndContentLength;
import com.structurizr.onpremises.domain.review.Review;
import com.structurizr.onpremises.domain.review.Session;
import com.structurizr.onpremises.util.AmazonS3ClientUtils;
import com.structurizr.util.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.StreamUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

import static com.structurizr.onpremises.configuration.StructurizrProperties.*;

class AmazonWebServicesS3ReviewDao implements ReviewDao {

    private static final Log log = LogFactory.getLog(AmazonWebServicesS3ReviewDao.class);

    private static final Pattern REVIEW_ID_PATTERN = Pattern.compile("[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}");

    private static final String TYPE_TAG = "type";
    private static final String IMAGE_TYPE = "image";
    private static final String JSON_TYPE = "json";

    private static final String REVIEW_JSON_FILENAME = "review.json";

    private final AmazonS3 amazonS3;
    private final String bucketName;

    AmazonWebServicesS3ReviewDao() {
        String accessKeyId = Configuration.getInstance().getProperty(AWS_S3_ACCESS_KEY_ID);
        String secretAccessKey = Configuration.getInstance().getProperty(AWS_S3_SECRET_ACCESS_KEY);
        String region = Configuration.getInstance().getProperty(AWS_S3_REGION);
        String endpoint = Configuration.getInstance().getProperty(AWS_S3_ENDPOINT);
        boolean pathStyleAccessEnabled = Boolean.parseBoolean(Configuration.getInstance().getProperty(AWS_S3_PATH_STYLE_ACCESS));

        this.amazonS3 = AmazonS3ClientUtils.create(accessKeyId, secretAccessKey, region, endpoint, pathStyleAccessEnabled);
        this.bucketName = Configuration.getInstance().getProperty(AWS_S3_BUCKET_NAME);
    }

    @Override
    public Set<String> getReviewIds() throws ReviewComponentException {
        Set<String> reviewIds = new HashSet<>();

        try {
            String folderKey = getBaseObjectName();

            ObjectListing listing = amazonS3.listObjects(bucketName, folderKey);
            List<S3ObjectSummary> files = listing.getObjectSummaries();

            while (listing.isTruncated()) {
                listing = amazonS3.listNextBatchOfObjects(listing);
                files.addAll(listing.getObjectSummaries());
            }

            for (S3ObjectSummary file : files) {
                String name = file.getKey().substring(folderKey.length() + 1);
                name = name.substring(0, name.indexOf("/"));
                if (REVIEW_ID_PATTERN.matcher(name).matches()) {
                    reviewIds.add(name);
                }
            }
        } catch (Exception e) {
            log.info(e.getMessage());
        }

        return reviewIds;
    }

    @Override
    public void putReview(Review review) throws ReviewComponentException {
        try {
            String objectKey = getBaseObjectName(review.getId()) + REVIEW_JSON_FILENAME;

            String json = Review.toJson(review);
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            InputStream inputStream = new ByteArrayInputStream(bytes);

            ObjectMetadata objectMetadata = new ObjectMetadata();
            objectMetadata.setContentLength(bytes.length);

            PutObjectRequest putRequest = new PutObjectRequest(bucketName, objectKey, inputStream, objectMetadata);
            putRequest.setTagging(new ObjectTagging(Collections.singletonList(new Tag(TYPE_TAG, JSON_TYPE))));
            putRequest.setMetadata(objectMetadata);

            amazonS3.putObject(putRequest);
        } catch (Exception e) {
            log.error(e);
            throw new ReviewComponentException("Could not create review");
        }
    }

    @Override
    public Review getReview(String reviewId) throws ReviewComponentException {
        InputStream inputStream = null;
        try {
            String objectKey = getBaseObjectName(reviewId) + REVIEW_JSON_FILENAME;
            GetObjectRequest getRequest = new GetObjectRequest(bucketName, objectKey);

            S3Object s3Object = amazonS3.getObject(getRequest);
            inputStream = s3Object.getObjectContent();

            String json = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
            Review review = Review.fromJson(json);

            if (review.getDateCreated() == null) {
                review.setDateCreated(s3Object.getObjectMetadata().getLastModified());
            }

            return review;
        } catch (Throwable t) {
            return null;
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public void submitReview(String reviewId, Session reviewSession) throws ReviewComponentException {
        try {
            String objectKey = getBaseObjectName(reviewId) + "comments-" + new Date().getTime() + ".json";

            String json = Session.toJson(reviewSession);
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            InputStream inputStream = new ByteArrayInputStream(bytes);

            ObjectMetadata objectMetadata = new ObjectMetadata();
            objectMetadata.setContentLength(bytes.length);

            PutObjectRequest putRequest = new PutObjectRequest(bucketName, objectKey, inputStream, objectMetadata);
            putRequest.setTagging(new ObjectTagging(Collections.singletonList(new Tag(TYPE_TAG, JSON_TYPE))));
            putRequest.setMetadata(objectMetadata);

            amazonS3.putObject(putRequest);
        } catch (Exception e) {
            log.error(e);
            throw new ReviewComponentException("Could not submit review");
        }
    }

    @Override
    public Collection<Session> getReviewSessions(String reviewId) throws ReviewComponentException {
        Collection<Session> reviewSessions = new ArrayList<>();

        try {
            String folderKey = getBaseObjectName(reviewId);
            for (S3ObjectSummary file : amazonS3.listObjects(bucketName, folderKey).getObjectSummaries()) {
                String name = file.getKey().substring(folderKey.length());
                if (name.startsWith("comments-") && name.endsWith(".json")) {

                    GetObjectRequest getRequest = new GetObjectRequest(bucketName, file.getKey());
                    InputStream inputStream = amazonS3.getObject(getRequest).getObjectContent();
                    String json = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
                    inputStream.close();

                    reviewSessions.add(Session.fromJson(json));
                }
            }
        } catch (Exception e) {
            log.error(e);
        }

        return reviewSessions;
    }

    @Override
    public void putDiagram(String reviewId, String filename, byte[] bytes) throws ReviewComponentException {
        ObjectMetadata objectMetadata = new ObjectMetadata();
        String objectKey = getBaseObjectName(reviewId) + filename;
        objectMetadata.setContentLength(bytes.length);

        PutObjectRequest putRequest = new PutObjectRequest(bucketName, objectKey, new ByteArrayInputStream(bytes), objectMetadata);
        putRequest.setTagging(new ObjectTagging(Collections.singletonList(new Tag(TYPE_TAG, IMAGE_TYPE))));

        amazonS3.putObject(putRequest);
    }

    @Override
    public boolean reviewExists(String reviewId) {
        try {
            String objectKey = getBaseObjectName(reviewId);
            GetObjectMetadataRequest request = new GetObjectMetadataRequest(bucketName, objectKey);

            amazonS3.getObjectMetadata(request);
            return true;
        } catch (AmazonS3Exception e) {
            if (e.getStatusCode() == 404) {
                return false;
            } else {
                throw e;
            }
        }
    }

    @Override
    public InputStreamAndContentLength getDiagram(String reviewId, String filename) throws ReviewComponentException {
        try {
            String objectKey = getBaseObjectName(reviewId) + filename;

            GetObjectRequest getRequest = new GetObjectRequest(bucketName, objectKey);
            S3Object s3Object = amazonS3.getObject(getRequest);

            return new InputStreamAndContentLength(
                    s3Object.getObjectContent(),
                    s3Object.getObjectMetadata().getContentLength());
        } catch (AmazonS3Exception as3e) {
            if (as3e.getStatusCode() == 404) {
                // ignore this - the image doesn't exist
            } else {
                log.info(as3e.getMessage());
            }
        } catch (Exception e) {
            log.info(e.getMessage());
        }

        return null;
    }

    private String getBaseObjectName() {
        return "reviews";
    }

    private String getBaseObjectName(String reviewId) {
        return getBaseObjectName() + "/" + reviewId + "/";
    }

}