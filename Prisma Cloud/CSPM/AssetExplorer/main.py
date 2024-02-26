import json, requests, os, csv, threading

ak= os.environ.get("ACCESS_KEY")
secret = os.environ.get("SECRET")
region = "api4"
regions=["AWS Bahrain","AWS Canada","AWS Cape Town","AWS Frankfurt","AWS Hong Kong","AWS Hyderabad","AWS Ireland","AWS Israel","AWS Jakarta","AWS London","AWS Melbourne","AWS Milan","AWS Mumbai","AWS Ohio","AWS Oregon","AWS Osaka","AWS Paris","AWS Sao Paulo","AWS Seoul","AWS Singapore","AWS Spain","AWS Stockholm","AWS Sydney","AWS Tokyo","AWS UAE","AWS Zurich"]

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

def assets_inventory(reg):

    url = "https://api4.prismacloud.io/v2/resource/scan_info"

    payload={
        #"account.group": account_group,
        "timeType":"to_now",
        "timeUnit":"epoch",
        #"policy.complianceStandard":compliance_name,
        #"policy.complianceRequirement":requirement_name,
        #"scan.status":"failed",
        #"limit": 50,
        #"policy.complianceSection": section_id,
        #"cloud.type":"aws",
        "cloud.region":reg
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

def append_data(data, resour):
    data.append(resour)
    print("Data for "+resour['name']+" was added")

data=[]

for reg in regions:
    resources=assets_inventory(reg)
    for res in resources:
        t=threading.Thread(target=append_data, args=[data,res])
        t.start()
    t.join()

with open ("AWS assets in non-permited-regions.csv", "w", newline="", encoding="utf-8") as csvfile:
    fieldnames=list(data[0].keys())
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for row in data:
        filtered_row = {key: row.get(key, "unknown") for key in fieldnames}
        writer.writerow(filtered_row)
