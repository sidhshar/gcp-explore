# Getting Started with Google Container Registry

vim quickstart.sh

vim Dockerfile

chmod +x quickstart.sh

gcloud container builds submit --tag gcr.io/[PROJECT_ID]/quickstart-image .

vim cloudbuild.yaml

gcloud container builds submit --config cloudbuild.yaml .

gcloud auth configure-docker

docker run gcr.io/[PROJECT_ID]/quickstart-image




