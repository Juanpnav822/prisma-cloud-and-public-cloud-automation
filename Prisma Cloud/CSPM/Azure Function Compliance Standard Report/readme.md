This script gives you all the assets filtered by 9 specific compliance standards made in Prisma Cloud for Sura. Three for each main cloud (AWS, Azure and OCI) which correspond to each enviroment (Production, Development and Lab)
You can find these compliance names in the variable (list) named 'compliances'
One issue this scirpt have is, prisma's api endpoint to get these assets doesn't give you some assets like account/subscriptions/compartments, so some compliance sections, even if they have assets breaking the rule, won't appear in the report made by this script.

This Script rely on the existence of an Azure storage Account with two container blobs. The container blobs are the main container with the name of "compliance-standard-reports" and the container to store historical data called "historial-compliance-standard-reports". You need to have the connection string of this storage account and store it as enviroment variable on the machine you're running the script.

Also you need the access keys from Prisma Cloud CSPM and store them as envirment variables with the name: ACCESS_KEY and SECRET

# Requirements to run this script in local machine:
- Having 3.11.8+ Python installed
- Installing the libraries mentioned in requirement.txt file using 'pip install {Library}'
- Have access to prisma cloud with access keyss, with admin role,
- You have to have access to an storage account in azure and two containers created by having the connection string for this storage account. The container must have public access.
- Now replace all the global variables for the ones that fit you, the container names ariables are the storage account blob container literal names.
- Also the variables: compliances, accountGroup, ambiente, cloud and counter. Are closely related by eachother. Compliances are the standards the scripts will be using to make the analysis then accountgroups indexing are the corresponds account groups for the scope of each compliance. ambiente and cloud are simple description of each compliance and account group in prisma cloud, and the counter will determine when the analysis will be made to a csv file. The counter will add 1 value, starting from 0, for each compliance analysis done. When counter add 3 values, then will make this report for all the compliances and send it to the blob storage. Then the previous analysis will be erased from the cache and start with the next mcompliance if it's the case. You can edit this by editing the if condition called: 'if counter == 2 or counter == 5 or counter == 8:'
- You'll need to backspace all the code from where it says '# These are my local variables' in order that the entire script is not in the prismareports(*args) function.
 You can now run the script

# Requirements to succesfully deploy this azure function:
- Create and Elastic Premium Plan EP3 Function APP, having Python 3.11+ enviroment code base. Public access. This can be done while doing the next step depending on your method. Important this function app to be timer trigger.
- Set your new azure function locally using VS Code or CLI tools as Azure documentation says: https://learn.microsoft.com/en-us/azure/azure-functions/create-first-function-vs-code-python or https://learn.microsoft.com/en-us/azure/azure-functions/create-first-function-cli-python?tabs=linux%2Cbash%2Cazure-cli%2Cbrowser
- Files will be created, replace the three important files (host.json, requirements and the .py) with the files of this repo. While replacing the .py file, just copy paste the content.
- Before deploying your code, make sure your enviromental variables are set in the function app which are:
   ACCESS_KEY (akid from prisma cloud)
   SECRET (secret from prisma cloud)
   CONNECTION_STRING
- Deploy your workstation with vscode or cli tool to the function app.
- It should be running now.

This script rely on the existence of the 9 custom compliance standard in Prisma cloud made for sura.
Created & maintained by @Juanpnav822 for Netdata Colombia SAS
