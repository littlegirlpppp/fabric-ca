def getRepoURL() {
  sh "git config --get remote.origin.url > .git/remote-url"
  return readFile(".git/remote-url").trim()
}

void setBuildStatus(String message, String state) {
  repoUrl = getRepoURL()

  step([
      $class: "GitHubCommitStatusSetter",
      reposSource: [$class: "ManuallyEnteredRepositorySource", url: repoUrl],
      contextSource: [$class: "ManuallyEnteredCommitContextSource", context: "ci/jenkins/build-status"],
      errorHandlers: [[$class: "ChangingBuildStatusErrorHandler", result: "UNSTABLE"]],
      statusResultSource: [ $class: "ConditionalStatusResultSource", results: [[$class: "AnyBuildResult", message: message, state: state]] ]
  ]);
}

pipeline {
    agent any

    environment {
        DOCKER_NS     = "${DOCKER_REGISTRY}/twbc"
        EXTRA_VERSION = "build-${BUILD_NUMBER}"
    }

    stages {
        stage('Build Image') {
            steps {
                setBuildStatus("Build Started", "PENDING");
                sh '''
                make docker
                '''
            }
        }
        stage('Upload Image') {
            steps {
                sh 'aws ecr get-login-password | docker login --username AWS --password-stdin ${DOCKER_REGISTRY}'
                sh '''
                make docker-list 2>/dev/null | grep ^twbc | while read line
                do
                   docker tag $line ${line/:*/:latest}
                   docker push $line
                   docker push ${line/:*/:latest}
                   docker rmi $line
                done
                '''
            }
        }

        stage('Test Fabcar') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    script {
                        def result = build(
                            job: 'fabric-sample-gm',
                            propagate: false,
                            parameters: [
                                [$class: 'StringParameterValue', name: 'IMAGE_CA', value: sh(script: 'make fabric-ca-docker-list 2>/dev/null ', returnStdout: true).trim()],
                            ]
                        )
                        if (result.result.equals("SUCCESS")) {
                            echo "Passed Test Fabcar"
                        } else {
                            error "Failed Test Fabcar"
                        }
                    }
                }
            }
        }
    }

    post {
        success {
            setBuildStatus("Build succeeded", "SUCCESS");
        }
        unsuccessful {
            setBuildStatus("Build failed", "FAILURE");
        }
    }
}
