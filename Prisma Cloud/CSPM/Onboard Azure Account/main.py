import json, requests, os, subprocess, time
from jsonpath_ng import parse
from azure.cli.core import get_default_cli
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

region="api2"

def get_kv_secret(kv_name,secret_name):

    #The code will pause and wait for the user to log in through the web browser
    key_vault_url = "https://{}.vault.azure.net/".format(kv_name)
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

    retrieved_secret = secret_client.get_secret(secret_name)
    secret_value = retrieved_secret.value
    return secret_value

get_default_cli().invoke(['login'])
ak=get_kv_secret('access-keys-prisma','name')
secret=get_kv_secret('access-keys-prisma','secret')
region='api2'
get_default_cli().invoke(['logout'])

def session():
    url="https://{}.prismacloud.io/login".format(region)
    passw={"username":ak,"password":secret}
    payload=json.dumps(passw)
    headers={
        'Content-Type': 'application/json; charset=UTF-8',
        'Accept': 'application/json; charset=UTF-8'
    }
    response=requests.request("POST",url,headers=headers,data=payload)
    response=json.loads(response.text)
    session=response['token']
    return session

def getTerraformForTenant(session,tenantId):
    url='https://{}.prismacloud.io/cas/v1/azure_template'.format(region)
    payload={
        "accountType": "tenant",
        "tenantId": tenantId,
        "rootSyncEnabled": True,
        "features": [
            "Remediation"
        ],
        "deploymentType": "azure"
    }
    headers={
        'Content-Type': 'application/json; charset=UTF-8',
        "x-redlock-auth": session
    }
    payload=json.dumps(payload)
    r=requests.request('POST',url,headers=headers,data=payload)
    print(r.text)
    r=r.text
    return r

def getTerraformForSubscription(session,subscriptionId,tenantId,features):
    url='https://{}.prismacloud.io/cas/v1/azure_template'.format(region)
    payload={
        "accountType": "account",
        "subscriptionId": subscriptionId,
        "tenantId": tenantId,
        "features": features,
        "deploymentType": "azure"
    }
    headers={
        'Content-Type': 'application/json; charset=UTF-8',
        "x-redlock-auth": session
    }
    payload=json.dumps(payload)
    r=requests.request('POST',url,headers=headers,data=payload)
    print(r)
    r=r.text
    return r

def featuresListForSubscription(session):
    url="https://{}.prismacloud.io/cas/v1/features/cloud/azure".format(region)
    payload={
        "accountType": "account",
        "deploymentType": "azure",
    }
    headers={
        'Content-Type': 'application/json; charset=UTF-8',
        'Accept': 'application/json; charset=UTF-8',
        "x-redlock-auth": session
    }
    payload=json.dumps(payload)
    r=requests.request('POST',url,headers=headers,data=payload)
    r=r.text
    r=json.loads(r)
    r=r['supportedFeatures']
    print(r)
    return r

def featuresListForTenant(session):
    url="https://{}.prismacloud.io/cas/v1/features/cloud/azure".format(region)
    payload={
        "accountType": "tenant",
        "deploymentType": "azure",
    }
    headers={
        'Content-Type': 'application/json; charset=UTF-8',
        'Accept': 'application/json; charset=UTF-8',
        "x-redlock-auth": session
    }
    payload=json.dumps(payload)
    r=requests.request('POST',url,headers=headers,data=payload)
    r=r.text
    r=json.loads(r)
    r=r['supportedFeatures']
    print(r)
    return r

def onboardSubscription(clientId,accountId,name,clienSecret,tenantId,session):
    url="https://{}.prismacloud.io/cas/v1/azure_account".format(region)
    payload = json.dumps({
        "clientId": clientId,
        "cloudAccount": {
            "accountId": accountId,
            "accountType": "tenant",
            "name": name
        },
        "environmentType": "azure",
        # "features": [
        #     {
        #     "defaultMemberState": "enabled",
        #     "name": "Remediation",
        #     "state": "enabled"
        #     }
        # ],
        "key": clienSecret,
        "monitorFlowLogs": True,
        "tenantId": tenantId
    })
    headers={
        'Content-Type': 'application/json; charset=UTF-8',
        "x-redlock-auth": session
    }
    response=requests.request('POST',url,headers=headers,data=payload)
    print(response)
    print(response.text)
    return response

def generateTerraformFile(data, filename):
    with open(filename, 'w') as file:
        file.write(data)

def erase_terraform_json_path(json_obj, json_path):
    jsonpath_expr = parse(json_path)
    matches = [match for match in jsonpath_expr.find(json_obj)]
    
    for match in matches:
        parent = match.context.value
        key = match.path.fields[-1]
        
        if isinstance(parent, dict):
            del parent[key]
        elif isinstance(parent, list):
            parent.pop(key)

    return json_obj

def erase_terraform_file_json_path(file_path, json_path):
    with open(file_path, 'r') as file:
        terraform_data = json.load(file)

    modified_data = erase_terraform_json_path(terraform_data, json_path)

    with open(file_path, 'w') as file:
        json.dump(modified_data, file, indent=2)

def loginAzure():
    powershell_login_command = 'powershell.exe -Command "az login"'
    subprocess.call(powershell_login_command, shell=True)

def startTerraform():
    powershell_init_command = 'powershell.exe -Command "terraform init"'
    subprocess.call(powershell_init_command, shell=True)

def applyTerraform():
    powershell_init_command = 'powershell.exe -Command "terraform apply -auto-approve"'
    subprocess.call(powershell_init_command, shell=True)

def handler():

    accountType='tenant'#input('Do you want to onboard a "subscription" or a "tenant"?\n')

    if accountType=='subscription':

        subscriptionId='1f5b9980-3f6f-41bd-bdff-b005e7a2a380'#input('Please insert your subscription ID\n')
        tenantId='4a94dd37-adaa-4fa3-bca6-0bbfcc2466f9'#input('Please insert your tenant ID\n')

        print('Here are the features you can activate in Prisma Cloud:\n')

        validFeatures = featuresListForSubscription(session())

        selectedFeatures = []

        while True:
            user_input = input("\nEnter a feature ('ALL' or 'done' to finish): \n")

            if user_input == 'done':
                break
            
            if user_input == 'ALL':
                selectedFeatures=validFeatures
                break

            if user_input in validFeatures:
                selectedFeatures.append(user_input)
                print("feature added.")
            else:
                print("Invalid value. Please try again.\n")

        print("Selected features:\n")
        print(selectedFeatures)

        terraformData=getTerraformForSubscription(session(),subscriptionId,tenantId,selectedFeatures)

        terraformData=terraformData.replace('"'+'null_resource.check_roles'+'"'+',',"")
        terraformData=terraformData.replace('"'+'null_resource.check_roles'+'"',"")
        terraformData=terraformData.replace('"'+'time_sleep.wait_20_seconds'+'"'+',','"'+'time_sleep.wait_20_seconds'+'"')

        generateTerraformFile(terraformData,script_dir+'/Template.tf.json')

        erase_terraform_file_json_path(script_dir+'/Template.tf.json','$.resource.null_resource')

        print('\nYour Terraform template is ready\n')

        script_dir2='"'+script_dir+'"'
        subprocess.call(f'powershell.exe -Command "cd ""{script_dir2}"""')
        loginAzure()
        startTerraform()
        applyTerraform()

        while not os.path.exists(script_dir+"/terraform.tfstate"):
            time.sleep(1)
        
        with open(script_dir+"/terraform.tfstate") as f:
            state=json.load(f)
        
        json_path=parse("$.outputs")
        matches = [match.value for match in json_path.find(state)]
        if matches:
            output = matches[0]
        else:
            output = None

        clientId=output['c__application_client_id']['value']
        clientSecret=output['d__application_client_secret']['value']
        appId=output['e__enterprise_application_object_id']['value']

        print(clientId+'\n')
        print(clientSecret+'\n')
        print(appId+'\n')

        print('\nNow that the resources needed to onboard the subscription in PC are deployed, this subscription will be listed in PC\n')
        name=input('Please type the name you want for your subscription in PC\n')

        onboardSubscription(clientId,subscriptionId,name,clientSecret,tenantId)

    elif accountType=='tenant':
        tenantId='4a94dd37-adaa-4fa3-bca6-0bbfcc2466f9'#input('Please insert your tenant ID\n')
        print('Here are the features you can activate in Prisma Cloud:\n')

        validFeatures = featuresListForTenant(session())

        selectedFeatures = []

        while True:
            user_input = input("\nEnter a feature ('ALL' or 'done' to finish): \n")

            if user_input == 'done':
                break
            
            if user_input == 'ALL':
                selectedFeatures=validFeatures
                break

            if user_input in validFeatures:
                selectedFeatures.append(user_input)
                print("feature added.")
            else:
                print("Invalid value. Please try again.\n")

        print("Selected features:\n")
        print(selectedFeatures)

        terraformData=getTerraformForTenant(session(),tenantId)

        terraformData=terraformData.replace('"'+'null_resource.check_roles'+'"'+',',"")
        terraformData=terraformData.replace('"'+'null_resource.check_roles'+'"',"")
        terraformData=terraformData.replace('"'+'time_sleep.wait_20_seconds'+'"'+',','"'+'time_sleep.wait_20_seconds'+'"')

        generateTerraformFile(terraformData,script_dir+'/Template.tf.json')

        erase_terraform_file_json_path(script_dir+'/Template.tf.json','$.resource.null_resource')

        print('\nYour Terraform template is ready\n')

        script_dir2='"'+script_dir+'"'
        subprocess.call(f'powershell.exe -Command "cd ""{script_dir2}"""')
        loginAzure()
        startTerraform()
        applyTerraform()

    else:
        print('You selected an incorrect option\n')
        handler()



script_dir = os.path.dirname(os.path.abspath(__file__))
os.environ['PATH'] += os.pathsep + r'C:/terraform'
handler()
