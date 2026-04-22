FROM jenkins/jenkins:lts

USER root

# Install Docker CLI + curl
RUN apt-get update && apt-get install -y \
    docker.io \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN usermod -aG docker jenkins

USER jenkins

# Install all required plugins in one layer
# - configuration-as-code: reads jenkins.yaml on boot
# - job-dsl: lets JCasC create the pipeline job via script block
# - workflow-aggregator: the Pipeline plugin (was missing — caused "no Pipeline option")
# - git: SCM support for pulling Jenkinsfile from GitHub
# - pipeline-model-definition: declarative pipeline syntax
# - credentials-binding: lets pipeline steps use stored secrets
RUN jenkins-plugin-cli --plugins \
    configuration-as-code \
    job-dsl \
    workflow-aggregator \
    pipeline-model-definition \
    git \
    credentials-binding \
    antisamy-markup-formatter \
    build-timeout \
    timestamper \
    ws-cleanup

# Skip the setup wizard — JCasC handles everything
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"

# Point Jenkins at the JCasC config file
ENV CASC_JENKINS_CONFIG="/var/jenkins_casc/jenkins.yaml"

# Copy casc config into image
COPY casc/jenkins.yaml /var/jenkins_casc/jenkins.yaml
