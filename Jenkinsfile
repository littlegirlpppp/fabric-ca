pipeline {
    agent any

    environment {
        DOCKER_NS     = "twbc"
        EXTRA_VERSION = "build-${BUILD_NUMBER}"
    }

    stages {
        stage('Build Image') {
            steps {
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
                   docker tag $line $DOCKER_REGISTRY/$line
                   docker tag $line $DOCKER_REGISTRY/${line/:*/:latest}
                   docker push $DOCKER_REGISTRY/$line
                   docker push $DOCKER_REGISTRY/${line/:*/:latest}
                   docker rmi $line $DOCKER_REGISTRY/$line
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
}
