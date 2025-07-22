library("deckers-pipeline-library")
nodeServerContainerPipeline([
    devGroup : 'deckers-devops',
    autoDeploy: false,
    teamName:settings.dvfTeamsName(),
    teamUrl:settings.dvfTeamsUrl(),
    publishImage: true,
    publishPackage: false,
    publishImagePackages:[
        ['key':'dify-api','path':'/api','file':'Dockerfile'],
        ['key':'dify-web','path':'/web','file':'Dockerfile']
    ],
    version: '1.6.1'
])
