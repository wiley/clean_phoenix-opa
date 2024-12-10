def ckLib = library(
  identifier: 'ck_ip_jenkins_library@fix/SGP-1754',
  retriever: modernSCM([
    $class: 'GitSCMSource',
    remote: 'git@github.com:wiley/ck_ip_jenkins_library.git',
    credentialsId: 'babee6c1-14fe-4d90-9da0-ffa7068c69af'
  ])
)

phoenixDjangoPipeline(
  dockerImageName: 'phoenix-opa',
  namespacePrefix:'phoenix'
)
