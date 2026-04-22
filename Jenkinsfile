pipeline {
    agent any
    parameters {
        string(name: 'DUMP_ID',     description: 'Case dump ID from database')
        string(name: 'DUMP_FILE',   description: 'Filename of memory dump')
        string(name: 'VOL_VERSION', defaultValue: 'auto', description: 'vol2 | vol3 | auto')
    }
    environment {
        // FIX #5a — paths now match the volume mounts in docker-compose.yml for ALL containers
        DUMP_PATH  = "/app/dumps/${params.DUMP_FILE}"
        REPORT_DIR = "/app/reports/${params.DUMP_ID}"
        FLASK_URL  = "http://memsuite_flask:5000"
    }
    stages {

        stage('Setup') {
            steps {
                echo "Initializing analysis for dump: ${params.DUMP_FILE} (id: ${params.DUMP_ID})"
                sh "mkdir -p ${REPORT_DIR}"
                sh "echo 'ANALYZING' > ${REPORT_DIR}/status.txt"
                sh """curl -sf -X POST ${FLASK_URL}/api/internal/status \
                    -H 'Content-Type: application/json' \
                    -d '{"dump_id":"${params.DUMP_ID}","status":"ANALYZING"}' || true"""
            }
        }

        stage('Integrity Verification') {
            steps {
                script {
                    // FIX #5a — dump is at /app/dumps inside Jenkins container (same volume mount)
                    def hash = sh(
                        script: "sha256sum ${DUMP_PATH} | awk '{print \$1}'",
                        returnStdout: true
                    ).trim()
                    sh "echo 'SHA256:${hash}' > ${REPORT_DIR}/integrity.log"
                    echo "SHA-256: ${hash}"
                }
            }
        }

        stage('Version Detection') {
            steps {
                script {
                    // FIX #2 — docker exec works now that Jenkins Dockerfile installs docker.io
                    def info = sh(
                        script: "docker exec memsuite_vol3 python3 -m volatility3 -f ${DUMP_PATH} windows.info 2>/dev/null || echo 'FAILED'",
                        returnStdout: true
                    ).trim()

                    if (info.contains('FAILED') || info.isEmpty()) {
                        env.VOL_CMD_BASE = "docker exec memsuite_vol2 python /opt/volatility/vol.py -f ${DUMP_PATH}"
                        env.VOL_VER      = "vol2"
                    } else {
                        env.VOL_CMD_BASE = "docker exec memsuite_vol3 python3 -m volatility3 -f ${DUMP_PATH}"
                        env.VOL_VER      = "vol3"
                    }
                    echo "Using: ${env.VOL_VER}"
                }
            }
        }

        stage('Profile Detection') {
            // Only needed for Vol2 — Vol3 auto-detects
            when { expression { env.VOL_VER == 'vol2' } }
            steps {
                script {
                    def profileRaw = sh(
                        script: """
                            ${env.VOL_CMD_BASE} imageinfo 2>/dev/null \
                            | grep 'Suggested Profile' \
                            | awk -F: '{print \$2}' \
                            | awk '{print \$1}' \
                            | tr -d ',' \
                            | head -1
                        """,
                        returnStdout: true
                    ).trim()

                    def profile = (profileRaw && profileRaw != '') ? profileRaw : 'Win7SP1x86'
                    echo "Detected profile: ${profile}"
                    sh "echo ${profile} > ${REPORT_DIR}/profile.txt"
                    env.VOL_CMD = "${env.VOL_CMD_BASE} --profile=${profile}"
                }
            }
        }

        stage('Finalise Command') {
            when { expression { env.VOL_VER == 'vol3' } }
            steps {
                script { env.VOL_CMD = env.VOL_CMD_BASE }
            }
        }

        stage('Process Analysis') {
            parallel {
                stage('pslist') {
                    steps {
                        script {
                            def plugin = (env.VOL_VER == 'vol3') ? 'windows.pslist' : 'pslist'
                            sh "${env.VOL_CMD} ${plugin} > ${REPORT_DIR}/pslist.txt 2>&1"
                        }
                    }
                }
                stage('psscan') {
                    steps {
                        script {
                            def plugin = (env.VOL_VER == 'vol3') ? 'windows.psscan' : 'psscan'
                            sh "${env.VOL_CMD} ${plugin} > ${REPORT_DIR}/psscan.txt 2>&1"
                        }
                    }
                }
            }
        }

        stage('Network Analysis') {
            steps {
                script {
                    def plugin = (env.VOL_VER == 'vol3') ? 'windows.netscan' : 'netscan'
                    sh "${env.VOL_CMD} ${plugin} > ${REPORT_DIR}/netscan.txt 2>&1"
                }
            }
        }

        stage('Code Injection Detection') {
            steps {
                script {
                    def plugin = (env.VOL_VER == 'vol3') ? 'windows.malfind' : 'malfind'
                    sh "${env.VOL_CMD} ${plugin} > ${REPORT_DIR}/malfind.txt 2>&1"
                }
            }
        }

        stage('Correlation & Scoring') {
            steps {
                sh "echo 'CORRELATING' > ${REPORT_DIR}/status.txt"
                sh """curl -sf -X POST ${FLASK_URL}/api/internal/status \
                    -H 'Content-Type: application/json' \
                    -d '{"dump_id":"${params.DUMP_ID}","status":"CORRELATING"}' || true"""
                sh """docker exec memsuite_flask python /app/pipeline.py correlate \
                    --dump-id ${params.DUMP_ID} \
                    --report-dir ${REPORT_DIR}"""
            }
        }

        stage('Report Generation') {
            steps {
                sh "echo 'REPORTING' > ${REPORT_DIR}/status.txt"
                sh """curl -sf -X POST ${FLASK_URL}/api/internal/status \
                    -H 'Content-Type: application/json' \
                    -d '{"dump_id":"${params.DUMP_ID}","status":"REPORTING"}' || true"""
                sh """docker exec memsuite_flask python /app/report_gen.py \
                    --dump-id ${params.DUMP_ID} \
                    --report-dir ${REPORT_DIR}"""
            }
        }
    }

    post {
        success {
            sh "echo 'COMPLETE' > ${REPORT_DIR}/status.txt"
            sh """curl -sf -X POST ${FLASK_URL}/api/internal/status \
                -H 'Content-Type: application/json' \
                -d '{"dump_id":"${params.DUMP_ID}","status":"COMPLETE"}' || true"""
            echo "Analysis complete for ${params.DUMP_ID}"
        }
        failure {
            sh "echo 'FAILED' > ${REPORT_DIR}/status.txt || true"
            sh """curl -sf -X POST ${FLASK_URL}/api/internal/status \
                -H 'Content-Type: application/json' \
                -d '{"dump_id":"${params.DUMP_ID}","status":"FAILED"}' || true"""
        }
        aborted {
            sh "echo 'FAILED' > ${REPORT_DIR}/status.txt || true"
            sh """curl -sf -X POST ${FLASK_URL}/api/internal/status \
                -H 'Content-Type: application/json' \
                -d '{"dump_id":"${params.DUMP_ID}","status":"FAILED"}' || true"""
        }
    }
}
