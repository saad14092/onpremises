package com.structurizr.onpremises.component.review;

import com.structurizr.onpremises.domain.User;
import com.structurizr.onpremises.domain.review.Comment;
import com.structurizr.onpremises.domain.review.Review;
import com.structurizr.onpremises.domain.review.ReviewType;
import com.structurizr.onpremises.domain.review.Session;
import com.structurizr.onpremises.configuration.Configuration;
import com.structurizr.onpremises.domain.InputStreamAndContentLength;
import com.structurizr.onpremises.util.DateUtils;
import com.structurizr.onpremises.util.RandomGuidGenerator;
import com.structurizr.util.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.structurizr.onpremises.configuration.StructurizrProperties.*;

class ReviewComponentImpl implements ReviewComponent {

    private static final Log log = LogFactory.getLog(ReviewComponentImpl.class);

    private static final String PNG_DATA_URI_PREFIX = "data:image/png;base64,";
    private static final String JPG_DATA_URI_PREFIX = "data:image/jpeg;base64,";
    private static final String PNG_FILE_EXTENSION = ".png";
    private static final String JPG_FILE_EXTENSION = ".jpg";
    private static final String COMMA = ",";

    private final ReviewDao reviewDao;

    ReviewComponentImpl() {
        String dataStorageImplementationName = Configuration.getInstance().getProperty(DATA_STORAGE_IMPLEMENTATION);

        if (AMAZON_WEB_SERVICES_S3.equals(dataStorageImplementationName)) {
            this.reviewDao = new AmazonWebServicesS3ReviewDao();
        } else {
            this.reviewDao = new FileSystemReviewDao();
        }
    }

    ReviewComponentImpl(ReviewDao dao) {
        this.reviewDao = dao;
    }

    @Override
    public Review createReview(User user, Long workspaceId, String[] files, ReviewType type) {
        try {
            List<FileTypeAndContent> diagrams = new ArrayList<>();

            for (String file : files) {
                if (file.startsWith(PNG_DATA_URI_PREFIX)) {
                    String base64Image = file.split(COMMA)[1];
                    byte[] decodedImage = Base64.getDecoder().decode(base64Image.getBytes(StandardCharsets.UTF_8));
                    diagrams.add(new FileTypeAndContent(PNG_FILE_EXTENSION, decodedImage));
                } else if (file.startsWith(JPG_DATA_URI_PREFIX)) {
                    String base64Image = file.split(COMMA)[1];
                    byte[] decodedImage = Base64.getDecoder().decode(base64Image.getBytes(StandardCharsets.UTF_8));
                    diagrams.add(new FileTypeAndContent(JPG_FILE_EXTENSION, decodedImage));
                }
            }

            if (diagrams.size() == 0) {
                throw new ReviewException("One or more PNG/JPG diagrams are needed to create a review.");
            }

            RandomGuidGenerator generator = new RandomGuidGenerator();
            String reviewId = generator.generate();
            while (reviewDao.reviewExists(reviewId)) {
                reviewId = generator.generate();
            }

            Review review = new Review(reviewId, user.getUsername());
            review.setType(type);
            review.setWorkspaceId(workspaceId);
            review.setDateCreated(DateUtils.getNow());

            int count = 1;
            for (FileTypeAndContent diagram : diagrams) {
                String filename = count + diagram.getExtension();
                reviewDao.putDiagram(reviewId, filename, diagram.getContent());
                review.addDiagram(count, "/review/" + reviewId + "/" + filename);
                count++;
            }

            reviewDao.putReview(review);

            return review;
        } catch (Exception e) {
            e.printStackTrace();
            throw new ReviewException("There was a problem creating a review.");
        }
    }

    @Override
    public Collection<Review> getReviews() {
        try {
            List<Review> reviews = new ArrayList<>();

            Set<String> reviewIds = reviewDao.getReviewIds();
            for (String reviewId : reviewIds) {
                reviews.add(getReview(reviewId, false));
            }

            return reviews;
        } catch (Exception e) {
            log.error("There was a problem getting the reviews", e);
            throw new ReviewException("There was a problem getting the reviews");
        }
    }

    @Override
    public Review getReview(String reviewId) {
        return getReview(reviewId, true);
    }

    private Review getReview(String reviewId, boolean includeComments) {
        try {
            Review review = reviewDao.getReview(reviewId);

            if (includeComments) {
                Collection<Session> reviewSessions = reviewDao.getReviewSessions(reviewId);
                for (Session reviewSession : reviewSessions) {
                    for (Comment comment : reviewSession.getComments()) {
                        if (!StringUtils.isNullOrEmpty(reviewSession.getAuthor())) {
                            comment.setAuthor(reviewSession.getAuthor());
                        }

                        review.addComment(comment);
                    }
                }
            }

            return review;
        } catch (Exception e) {
            log.error("There was a problem getting the review with ID " + reviewId, e);
            throw new ReviewException("There was a problem getting the review with ID " + reviewId);
        }
    }

    @Override
    public InputStreamAndContentLength getDiagram(String reviewId, String filename) {
        try {
            return reviewDao.getDiagram(reviewId, filename);
        } catch (Exception e) {
            log.error("Error while trying to get image " + filename + " for review with ID " + reviewId, e);
            throw new ReviewException("Error while trying to get image " + filename + " for review with ID " + reviewId);
        }
    }

    @Override
    public void submitReview(String reviewId, Session reviewSession) {
        try {
            reviewDao.submitReview(reviewId, reviewSession);
        } catch (Exception e) {
            log.error("There was a problem getting the review with ID " + reviewId, e);
            throw new ReviewException("There was a problem getting the review with ID " + reviewId);
        }
    }

    @Override
    public void lockReview(String reviewId) {
        try {
            Review review = reviewDao.getReview(reviewId);
            review.setLocked(true);

            reviewDao.putReview(review);
        } catch (Exception e) {
            log.error("Error locking review " + reviewId, e);
            throw new ReviewException("Error locking review " + reviewId, e);
        }
    }

    @Override
    public void unlockReview(String reviewId) {
        try {
            Review review = reviewDao.getReview(reviewId);
            review.setLocked(false);

            reviewDao.putReview(review);
        } catch (Exception e) {
            log.error("Error unlocking review " + reviewId, e);
            throw new ReviewException("Error unlocking review " + reviewId, e);
        }
    }

}