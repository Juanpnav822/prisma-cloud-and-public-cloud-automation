import importlib
import subprocess

def install_package(package_name):
    subprocess.check_call(['pip', 'install', package_name])

# List of required libraries
required_libraries = ['xlsxwriter','openpyxl','azure.keyvault.secrets', 'azure.cli.core','azure.identity','requests','pandas']
firststep=True

# Check if libraries are installed
for library in required_libraries:
    try:
        importlib.import_module(library)
    except ImportError:
        try:
            install_package(str.replace(library,'.','-'))
            if firststep==True:
                install_package('azure-cli')
                install_package('openpyxl xlrd')
                install_package('xlsxwriter')
                firststep=False
        except:
            print("The {} library is missing. Please install it using: 'pip install {}'. Then restart the script".format(library,str.replace(library,'.','-')))
            exit(1)

from azure.cli.core import get_default_cli
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import requests, json, csv
from datetime import datetime
import pandas as pd
from openpyxl import Workbook

#Get secrets
def get_kv_secret(kv_name,secret_name):

    #The code will pause and wait for the user to log in through the web browser
    key_vault_url = "https://{}.vault.azure.net/".format(kv_name)
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

    retrieved_secret = secret_client.get_secret(secret_name)
    secret_value = retrieved_secret.value
    return secret_value

#This function return the token used in all api auths
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

#supposely to extend the session but it's not working
def extend_session(token):
    url = "https://{}.prismacloud.io/auth_token/extend".format(region)
    headers = {
        "Accept": "application/json; charset=UTF-8",
        "x-redlock-auth": token
    }
    resp = requests.request("GET", url, headers=headers)
    return resp

#This Function return a list of all account onboarded in Prisma Cloud
def allAccounts(session,cloudType):
    url="https://{}.prismacloud.io/cloud/name".format(region)
    
    payload={
        "cloud":cloudType,
    }
    headers={
        "Accept": "application/json; charset=UTF-8",
        "x-redlock-auth": session
    }

    response=requests.request('GET',url,headers=headers)
    response=json.loads(response.content)
    return response

#This function return a list where the main keys are name and accounts[]
def accountGroups(session):
    url="https://{}.prismacloud.io/cloud/group".format(region)
    headers={
        "Accept": "application/json; charset=UTF-8",
        "x-redlock-auth": session
    }

    response=requests.request('GET',url,headers=headers)
    accGroups=json.loads(response.content)
    allAG=[]
    for x in accGroups:
        allAG.append(x['name'])
    return accGroups

#This function will return a list of compliance standards where the main keys are id and name
def compStandards(session):
    url = "https://{}.prismacloud.io/compliance".format(region)
    headers = {
        'Accept': 'application/json; charset=UTF-8',
        'x-redlock-auth': session
    }
    
    response=requests.request("GET",url,headers=headers)
    response=json.loads(response.content)
    allcomp=[]
    for x in response:
        allcomp.append(x['name'])
    return response

#This function will return a list of requirements of a standard where the main key is the id and name
def compStandardReq(session,stndId):
    url="https://{}.prismacloud.io/compliance/{}/requirement".format(region,stndId)
    headers={
        'Accept': 'application/json; charset=UTF-8',
        'x-redlock-auth': session
    }

    response=requests.request("GET",url,headers=headers)
    response=json.loads(response.content)
    return response

#This function will return a list of sections of a requirements of a specific compliance standard
def compStandardSec(session,ReqId):
    url="https://{}.prismacloud.io/compliance/{}/section".format(region,ReqId)
    headers={
        'Accept': 'application/json; charset=UTF-8',
        'x-redlock-auth': session
    }

    response=requests.request("GET",url,headers=headers)
    response=json.loads(response.content)
    return response

#This function will return a list of the posture of a requirement of a compliance standard
def complianceStandarPosture(session,stdID,reqID,account,sectname,group):
    url="https://{}.prismacloud.io/compliance/posture/{}/{}".format(region,stdID,reqID)
    payload={"timeType":"to_now","timeUnit":"epoch","cloud.account": account}
    headers={
        'Accept': 'application/json; charset=UTF-8',
        'x-redlock-auth': session
    }
    try:
        response=requests.request("GET",url,headers=headers,params=payload)
        response=json.loads(response.content)

        for x in response['complianceDetails']:
            extend_session(session)
            x['Section']=sectname
            if x['totalResources']>0:
                x['Cloud Accounts']=account
            else:
                x['Cloud Accounts']=group+'(Account Group)'
            x['Account Group']=group

        posture=response['complianceDetails']

        return posture
    except:
        print('There was an error with ',reqID,' and ',account)

#Affected assets by account group
def assetsExplorerByAccountGroup(token,secID,accGroup,std):
    url = "https://{}.prismacloud.io/resource/scan_info".format(region)
    payload={
                "timeType":"to_now",
                "timeUnit":"epoch",
                "account.group":accGroup,
                #"scan.status":"failed",
                "policy.complianceStandard":std,
                #"policy.complianceRequirement":reqID,
                "policy.complianceSection":secID
            }
    
    headers = {
        'Accept': 'application/json; charset=UTF-8',
        'x-redlock-auth': token
    }

    try:
        r = requests.request("GET", url, headers=headers, params=payload)
        response = json.loads(r.content)
        response = response['resources']
        return response
    except:
        print('There it was an error making assets explorer report for',secID,'section\n')

#Affected assets by cloud account
def assetsExplorerByCloudAccount(token,secID,acc,std):
    url = "https://{}.prismacloud.io/resource/scan_info".format(region)
    payload={
                "timeType":"to_now",
                "timeUnit":"epoch",
                "cloud.account":acc,
                #"scan.status":"failed",
                "policy.complianceStandard":std,
                #"policy.complianceRequirement":reqID,
                "policy.complianceSection":secID
            }
    
    headers = {
        'Accept': 'application/json; charset=UTF-8',
        'x-redlock-auth': token
    }

    try:
        r = requests.request("GET", url, headers=headers, params=payload)
        response = json.loads(r.content)
        response = response['resources']
        return response
    except:
        print('There it was an error making assets explorer report for',secID,'section\n')

#Here will define the build of a json file just for testing purposes
def write_json(object, filename):
    with open(filename, 'w') as outfile:
        json.dump(object, outfile)

#Simple write csv function
def write_csv(list, filename):
    data_file = open('%s.csv' % filename, 'w', newline='')
    count = 0
    csv_writer = csv.writer(data_file)

    for x in list:
        if count == 0:
            header=x.keys()
            csv_writer.writerow(header)
            count+=1
        csv_writer.writerow(x.values())
    data_file.close()

#This function will eat a list of lists of dictionories and will rewrite it to merge those dicts that have the same id value, 
#in a single dict within the same list
def merge_posture_by_id(final):
    merged_dicts = {}
    for dict_list in final:
        for dictionary in dict_list:
            id_value = dictionary['id']
            if id_value not in merged_dicts:
                merged_dicts[id_value] = dictionary.copy()
            else:
                for key, value in dictionary.items():
                    if key != 'id':
                        if isinstance(value, int) and key!='assignedPolicies':
                            merged_dicts[id_value][key] += value
                        elif isinstance(value, str):
                            if value not in merged_dicts[id_value][key]:
                                merged_dicts[id_value][key] += ',' + value
    return list(merged_dicts.values())

#This function will remove the collumns that we don't need
def removeKeys(dict_list, key_to_remove):
    for dictionary in dict_list:
        dictionary.pop(key_to_remove, None)

#Remove a word withing a string where this string is a value in multiple dicts that are contained in an array
def remove_word_from_cloud_accounts(dict_list, word_to_remove):
    for dictionary in dict_list:
        if 'Cloud Accounts' in dictionary:
            cloud_accounts = dictionary['Cloud Accounts']
            cloud_accounts = cloud_accounts.replace(word_to_remove, '').strip()
            dictionary['Cloud Accounts'] = cloud_accounts

#Function to merge csv files
def merge_csv_to_excel(csv_files, excel_file):
    with pd.ExcelWriter(excel_file, engine='xlsxwriter') as writer:
        for csv_file in csv_files:
            df = pd.read_csv(csv_file)
            sheet_name = csv_file[:31]  # Truncate sheet name to 31 characters
            df.to_excel(writer, sheet_name=sheet_name, index=False)

#Global Variables
get_default_cli().invoke(['login'])
ak=get_kv_secret('access-keys-prisma','name')
secret=get_kv_secret('access-keys-prisma','secret')
region='api2'
get_default_cli().invoke(['logout'])

#Let's define the main function here where will work as the processor and the handler at the same time.
def handler_and_stuff():
    
    token=session()
    firstIndex=True
    allAccountGroups=accountGroups(token)
    stringOfAccGroups=''

    for x in allAccountGroups:
        if firstIndex==True:
            stringOfAccGroups=x['name']
            firstIndex=False
        else:
            stringOfAccGroups=stringOfAccGroups+', '+x['name']
    
    firstIndex=True
    print('\n',stringOfAccGroups)
    accGroup=input('\n\nInsert one of the account group listed above: ')
    all_accounts=[]
    for i in allAccounts(session(),'all'):
        all_accounts.append(i['name'])
    accounts=[]
    std={}
    for x in allAccountGroups:
        if x['name']==accGroup:
            accounts.append(x['accounts'])
            break
    if accounts==[]:
        stringofallaccounts=''
        for x in all_accounts:
            if firstIndex==True:
                stringofallaccounts=x
                firstIndex=False
            else:
                stringofallaccounts=stringofallaccounts+', '+x
        print('\n',stringofallaccounts)
        optionalAccMethod=input('\nAccount Group was not found. If you prefer select a single Cloud Account, type its name (above you have a list of all possible options): ')
        for x in all_accounts:
            if x==optionalAccMethod:
                accounts=[[{'name':optionalAccMethod}]]
                accounts=accounts[0]
                print('\n',accounts[0]['name'],'was selected to be analyzed\n')
                accGroup='no account group in Prisma Cloud was selected for this report'
                break
        if accounts==[]:    
            accGroup='Default Account Group'
            for i in allAccountGroups:
                if i['name']=='Default Account Group':
                    accounts.append(i['accounts'])
            accounts=accounts[0]
            print('\nAccount Group or single account was not found, using Default Account Group instead\n')          
    else:
        accounts=accounts[0]
        print('Using',accGroup,'as you selected')
    allCompStd=compStandards(token)
    firstIndex=True
    namesOfCompStd=''
    for x in allCompStd:
        if firstIndex==True:
            namesOfCompStd=x['name']
            firstIndex=False
        else:
            namesOfCompStd=namesOfCompStd+', '+x['name']
    firstIndex=True

    print('\n',namesOfCompStd)

    stdInput=input('\nNow insert one of the compliance standards listed above: ')
    for x in allCompStd:
        if x['name']==stdInput:
            std.update(x)
            break
    if std=={}:
        print('\nCompliance standard was not found')
        for x in allCompStd:
            if x['name']=='CIS v1.4.0 (Azure)':
                std.update(x)
                break

    nameOfAccounts=[]
    for i in accounts:
        nameOfAccounts.append(i['name'])
    stringOfAccounts=''
    index=True
    for value in nameOfAccounts:
        if index == True:
            stringOfAccounts=value
            index=False
        else:
            stringOfAccounts=stringOfAccounts+', '+value

    print('\nUsing',std['name'],'for compliance standard posture report for the following accounts:\n',stringOfAccounts)
    allReqs=compStandardReq(token,std['id'])
    report=[]
    #name=accGroup

    print('\nMaking Compliance Standard Report, this may take several minutes...')
    for x in allReqs:
        for y in accounts:
            report.append(complianceStandarPosture(session(),std['id'],x['id'],y['name'],x['name'],accGroup))
            print(x['name'],'requirement posture report for',y['name'],'was done')
    
    print("\nNow the data it's being summarized, please wait...\n")

    report=merge_posture_by_id(report)
    removeKeys(report,'id')
    removeKeys(report,'default')
    #removeKeys(report,'assignedPolicies')
    newvariable=accGroup+','
    remove_word_from_cloud_accounts(report,newvariable+'(Account Group)')
    newvariable=','+accGroup
    remove_word_from_cloud_accounts(report,newvariable+'(Account Group)')
    remove_word_from_cloud_accounts(report,accGroup+'(Account Group)')
    #write_json(report,'byreq.json')

    nowvalue = datetime.now()
    dt_string = nowvalue.strftime("%Y-%m-%d_%H_%M_%S")

    compNewName=std['name']
    compNewName=compNewName.replace(" ","-")

    filename="Compliance-standard-report-{}-{}".format(compNewName,dt_string)
    write_csv(report,filename)

    print("Your posture compliance standard report is ready to go!\n")

    assets=[]
    allSectID=[]

    for x in allReqs:
        allSectID.append(compStandardSec(session(),x['id']))

    print('\nMaking assets explorer report for existingzzz resources, this may take even more minutes...\n')

    allfiles=[filename+'.csv']

    if accGroup!='no account group in Prisma Cloud was selected for this report':
        for x in allSectID:
            for y in x:
                print('Making Assets report for',y['sectionId'],'section...')
                communistVariable=assetsExplorerByAccountGroup(session(),y['sectionId'],accGroup,std['name'])
                assets.append(assetsExplorerByAccountGroup(session(),y['sectionId'],accGroup,std['name']))

                if communistVariable!=[]:
                    write_csv(communistVariable,y['sectionId']+'-'+y['description']+'-'+filename+'-'+'section-report')
                    allfiles.append(y['sectionId']+'-'+y['description']+'-'+filename+'-'+'section-report'+'.csv')
                communistVariable=[]

    else:
        for x in allSectID:
            for y in x:
                print('Making Assets report for',y['sectionId'],'section...')
                communistVariable=assetsExplorerByCloudAccount(session(),y['sectionId'],accounts[0]['name'],std['name'])
                assets.append(assetsExplorerByCloudAccount(session(),y['sectionId'],accounts[0]['name'],std['name']))

                if communistVariable!=[]:
                    write_csv(communistVariable,y['sectionId']+'-'+y['description']+'-'+filename+'-'+'section-report')
                    allfiles.append(y['sectionId']+'-'+y['description']+'-'+filename+'-'+'section-report'+'.csv')
                communistVariable=[]

    merge_csv_to_excel(allfiles,filename+'-full-version.xlsx')   

handler_and_stuff()
