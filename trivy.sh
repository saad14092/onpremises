#docker run aquasec/trivy image structurizr/onpremises
docker run -e "TRIVY_DB_REPOSITORY=public.ecr.aws/aquasecurity/trivy-db" -e "TRIVY_JAVA_DB_REPOSITORY=public.ecr.aws/aquasecurity/trivy-java-db" aquasec/trivy image structurizr/onpremises