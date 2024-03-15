import datetime
import logging
import azure.functions as func
import json, gc, os, requests, threading, csv
from azure.storage.blob import BlobServiceClient

app = func.FunctionApp()

# These are my global variables
ak= os.environ.get("ACCESS_KEY")
secret = os.environ.get("SECRET")
region = "api4"
connection_string = os.environ.get("CONNECTION_STRING")
container_name = "compliance-standard-reports"
container_name2 = 'historial-compliance-standard-reports'

def token():
    url="https://{}.prismacloud.io/login".format(region)
    payload={
        "username":ak,
        "password":secret
    }
    payload=json.dumps(payload)
    headers={
        'Content-Type': 'application/json; charset=UTF-8',
        'Accept': 'application/json; charset=UTF-8'
    }
    response=requests.request("POST",url,headers=headers,data=payload)
    response=json.loads(response.content)
    # Token of Prisma Cloud session
    return response['token']

def all_compliance_standards():

    url="https://{}.prismacloud.io/compliance".format(region)

    headers={
        "Accept": "application/json; charset=UTF-8",
        "x-redlock-auth": token()
    }

    response=requests.request("GET",url,headers=headers)
    response=json.loads(response.content)
    
    #[{"cloudType":[],"id":"","name":"",...},...]
    return response

def all_compliance_requirements(compliance_id):

    url="https://{}.prismacloud.io/compliance/{}/requirement".format(region,compliance_id)

    headers={
        "Accept": "application/json; charset=UTF-8",
        "x-redlock-auth": token()
    }

    response=requests.request("GET",url,headers=headers)
    response=json.loads(response.content)

    #[{"description":"Ensure that...","id":"","name":"iam","requirementId":"1",...},...]
    return response

def all_sections_of_a_compliance_requirement(requirement_id):

    url="https://{}.prismacloud.io/compliance/{}/section".format(region,requirement_id)

    headers={
        "Accept": "application/json; charset=UTF-8",
        "x-redlock-auth": token()
    }

    response=requests.request("GET",url,headers=headers)
    response=json.loads(response.content)

    #[{"description":"","id":"","sectionId":""},...]
    return response

def assets_explorer(account_group,compliance_name,requirement_name,section_id):

    url = "https://{}.prismacloud.io/v2/resource/scan_info".format(region)

    payload={
        "account.group": account_group,
        "timeType":"to_now",
        "timeUnit":"epoch",
        "policy.complianceStandard":compliance_name,
        "policy.complianceRequirement":requirement_name,
        "policy.complianceSection": section_id
        #"limit": 50
    }

    headers={
        'Accept': 'application/json; charset=UTF-8',
        'x-redlock-auth': token()
    }

    response=requests.request("GET",url,headers=headers,params=payload)
    response=json.loads(response.content)
    response=response['resources']

    #[{accountId:"",accountName:"",...},...]
    return response

def policy_severity(policy_id):

    url="https://{}.prismacloud.io/policy/{}".format(region,policy_id)

    headers={
        'Accept': 'application/json; charset=UTF-8',
        'x-redlock-auth': token()
    }

    response=requests.request('GET',url,headers=headers)
    response=json.loads(response.content)

    #string
    return response['severity']

def send_dicts_to_blob_storage(data, blob_service_client, container_name, blob_name):

    #Making the Header!
    headers = set()
    headers.update(data[0].keys())

    # Create a virtual file-like object using a TextIOBase subclass
    class VirtualTextIO:
        def __init__(self):
            self.buffer = []

        def write(self, s):
            self.buffer.append(s)

        def getvalue(self):
            return "".join(self.buffer)

    #Write CSV data to the virtual file-like object
    csv_file = VirtualTextIO()
    csv_writer = csv.DictWriter(csv_file, fieldnames=headers)
    csv_writer.writeheader()
    csv_writer.writerows(data)

    #Upload the CSV data to the blob
    try:
        blob_client = blob_service_client.get_blob_client(container_name, blob_name)
        blob_client.upload_blob(csv_file.getvalue(), content_type="text/csv", overwrite=True)
        print(f"Data successfully uploaded to blob '{blob_name}' in container '{container_name}'.")
        logging.info(f"Data successfully uploaded to blob '{blob_name}' in container '{container_name}'.")
    except Exception as e:
        print(f"Error uploading data: {e}")
        logging.info(f"Error uploading data: {e}")

def row_maker(main_data,asset,compliance_name,cloud,ambiente,section,requirement_name):

    # severity_guide=['','informational','low','medium','high','critical']
    # severities=asset['scannedPolicies']
    if asset == {}:

        asset={
            'name':'Resource not readable outside Prisma Cloud',
            'accountId':'Unknow_More info in Prisma Cloud',
            'accountName':'Unknow_More info in Prisma Cloud'
        }

        passed='Unknow'

        if section['associatedPolicyIds']!=[]:

            severity=policy_severity(section['associatedPolicyIds'][0])

        else:

            severity='Not assigned policy'
            
    else:
        severity=asset['scannedPolicies'][0]['severity']
        passed=asset['scannedPolicies'][0]['passed']
    
    # print(severity)
    # if len(severities) > 1:
        
    #     index=0

    #     for x in severities:
    #         for y in severity_guide:
    #             if x['severity']==y:
    #                 if severity_guide.index(y) > index:
    #                     severity=x['severity']
    #                     index=severity_guide.index(y)

    #     for x in severities:
    #         if x['passed']==False:
    #             passed=False
    #             break

    row={}
    row={
        'Cloud':cloud,
        'Compliance Standard':compliance_name,
        'Section ID': section['sectionId'],
        'Section Description': section['description'],
        'Requirement': requirement_name,
        'Resource': asset['name'],
        'Account ID': asset['accountId'],
        'Account Name': asset['accountName'],
        'Enviroment': ambiente,
        'Severity': severity,
        'Passed': passed
    }

    main_data.append(row.copy())

    del row

    gc.collect()

def data_maker(main_data,account_group,compliance_name,requirement_name,section,cloud,ambiente):

    allAssests=assets_explorer(account_group,compliance_name,requirement_name,section['sectionId'])
    if allAssests != []:
        for asset in allAssests:
            
            row_maker(main_data,asset,compliance_name,cloud,ambiente,section,requirement_name)
            t=threading.Thread(target=row_maker, args=[main_data,asset,compliance_name,cloud,ambiente,section,requirement_name])
            t.start()
        
        try:
            t.join()
            logging.info('Data created for {} {} {}'.format(section['sectionId'],section['description'],compliance_name))
            print('Data created for {} {} {}'.format(section['sectionId'],section['description'],compliance_name))
            
        except:
            logging.info('Error adding {} of {}'.format(section['sectionId'],compliance_name))
            print('Error adding {} of {}'.format(section['sectionId'],compliance_name))
    else:
        #row_maker(main_data,{},compliance_name,cloud,ambiente,section,requirement_name)

        logging.info('No resources found for {} {}'.format(section['sectionId'],compliance_name))
        print('No resources found for {} {}'.format(section['sectionId'],compliance_name))

@app.schedule(schedule="0 0 */12 * * *", arg_name="mytimer", run_on_startup=False,
              use_monitor=False) 
def azure_reports(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.UTC).replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')
    
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    compliances=['Estandar Sura Azure PDN V 1.0','Estandar Sura Azure DLLO V 1.0','Estandar Sura Azure LAB V 1.0']
    accountGroup=['Azure PDN Account Group','Azure DLLO Account Group','Azure LAB Account Group']
    ambiente=['Produccion','Desarrollo','Laboratorio']
    cloud=['azure','azure','azure']
    counter=0
    dataMain=[]
    for compliance in compliances:

        allCompliances=all_compliance_standards()

        compliance_id=""

        for x in allCompliances:
            
            if compliance == x['name']:

                compliance_id=x['id']
                break

        else:

            print('{} compliance standard was not found in Prisma Cloud\nSkipping this compliance standard...'.format(compliance))
            logging.info('{} compliance standard was not found in Prisma Cloud\nSkipping this compliance standard...'.format(compliance))
            counter=counter+1
            continue

        #[{"description":"Ensure that...","id":"","name":"iam","requirementId":"1",...},...]
        allRequirements=all_compliance_requirements(compliance_id)

        for requirement in allRequirements:

            requirement_id=requirement['id']
            requirement_name=requirement['name']

            allSections=all_sections_of_a_compliance_requirement(requirement_id)

            for section in allSections:

                data_maker(dataMain,accountGroup[counter],compliance,requirement_name,section,cloud[counter],ambiente[counter])
                
                # t = threading.Thread(target=data_maker, args=[dataMain,accountGroup[counter],compliance,requirement_name,section,cloud[counter],ambiente[counter]])
                # t.start()

            #t.join()

        if counter == 2:

            blob_service_client = BlobServiceClient.from_connection_string(connection_string)

            nowvalue = datetime.datetime.now()
            dt_string = nowvalue.strftime("%Y-%m-%d")

            send_dicts_to_blob_storage(dataMain,blob_service_client,container_name,'currentanalysis-'+cloud[counter]+'.csv')
            send_dicts_to_blob_storage(dataMain,blob_service_client,container_name2,'analysis-'+cloud[counter]+dt_string+".csv")

            logging.info('Blob created successfully!')

            dataMain=[]

        counter=counter+1

@app.schedule(schedule="0 30 */12 * * *", arg_name="mytimer", run_on_startup=False,
              use_monitor=False) 
def aws_reports(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.UTC).replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')
    
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    compliances=['Estandar Sura AWS PDN V 1.0','Estandar Sura AWS DLLO V 1.0','Estandar Sura AWS LAB V 1.0']
    accountGroup=['AWS PDN Account Group','AWS DLLO Account Group','AWS LAB Account Group']
    ambiente=['Produccion','Desarrollo','Laboratorio']
    cloud=['aws','aws','aws']
    counter=0
    dataMain=[]
    for compliance in compliances:

        allCompliances=all_compliance_standards()

        compliance_id=""

        for x in allCompliances:
            
            if compliance == x['name']:

                compliance_id=x['id']
                break

        else:

            print('{} compliance standard was not found in Prisma Cloud\nSkipping this compliance standard...'.format(compliance))
            logging.info('{} compliance standard was not found in Prisma Cloud\nSkipping this compliance standard...'.format(compliance))
            counter=counter+1
            continue

        #[{"description":"Ensure that...","id":"","name":"iam","requirementId":"1",...},...]
        allRequirements=all_compliance_requirements(compliance_id)

        for requirement in allRequirements:

            requirement_id=requirement['id']
            requirement_name=requirement['name']

            allSections=all_sections_of_a_compliance_requirement(requirement_id)

            for section in allSections:

                data_maker(dataMain,accountGroup[counter],compliance,requirement_name,section,cloud[counter],ambiente[counter])
                
                # t = threading.Thread(target=data_maker, args=[dataMain,accountGroup[counter],compliance,requirement_name,section,cloud[counter],ambiente[counter]])
                # t.start()

            #t.join()

        if counter == 2:

            blob_service_client = BlobServiceClient.from_connection_string(connection_string)

            nowvalue = datetime.datetime.now()
            dt_string = nowvalue.strftime("%Y-%m-%d")

            send_dicts_to_blob_storage(dataMain,blob_service_client,container_name,'currentanalysis-'+cloud[counter]+'.csv')
            send_dicts_to_blob_storage(dataMain,blob_service_client,container_name2,'analysis-'+cloud[counter]+dt_string+".csv")

            logging.info('Blob created successfully!')

            dataMain=[]

        counter=counter+1

@app.schedule(schedule="0 50 */12 * * *", arg_name="mytimer", run_on_startup=True,
              use_monitor=False) 
def oci_reports(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.UTC).replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')
    
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    compliances=['Estandar Sura OCI PDN V 1.0','Estandar Sura OCI DLLO V 1.0','Estandar Sura OCI LAB V 1.0']
    accountGroup=['OCI PDN Account Group','OCI DLLO Account Group','OCI LAB Account Group']
    ambiente=['Produccion','Desarrollo','Laboratorio']
    cloud=['oci','oci','oci']
    counter=0
    dataMain=[]
    for compliance in compliances:

        allCompliances=all_compliance_standards()

        compliance_id=""

        for x in allCompliances:
            
            if compliance == x['name']:

                compliance_id=x['id']
                break

        else:

            print('{} compliance standard was not found in Prisma Cloud\nSkipping this compliance standard...'.format(compliance))
            logging.info('{} compliance standard was not found in Prisma Cloud\nSkipping this compliance standard...'.format(compliance))
            counter=counter+1
            continue

        #[{"description":"Ensure that...","id":"","name":"iam","requirementId":"1",...},...]
        allRequirements=all_compliance_requirements(compliance_id)

        for requirement in allRequirements:

            requirement_id=requirement['id']
            requirement_name=requirement['name']

            allSections=all_sections_of_a_compliance_requirement(requirement_id)

            for section in allSections:

                data_maker(dataMain,accountGroup[counter],compliance,requirement_name,section,cloud[counter],ambiente[counter])
                
                # t = threading.Thread(target=data_maker, args=[dataMain,accountGroup[counter],compliance,requirement_name,section,cloud[counter],ambiente[counter]])
                # t.start()

            #t.join()

        if counter == 2:

            blob_service_client = BlobServiceClient.from_connection_string(connection_string)

            nowvalue = datetime.datetime.now()
            dt_string = nowvalue.strftime("%Y-%m-%d")

            send_dicts_to_blob_storage(dataMain,blob_service_client,container_name,'currentanalysis-'+cloud[counter]+'.csv')
            send_dicts_to_blob_storage(dataMain,blob_service_client,container_name2,'analysis-'+cloud[counter]+dt_string+".csv")

            logging.info('Blob created successfully!')

            dataMain=[]

        counter=counter+1
