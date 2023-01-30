#PoC Domain Squatting
#VirusTotal Search Submission
#By Sketchymoose
#Version 2.0

import requests
import json
import urllib.parse
import datetime
from datetime import timedelta

#Global Variables
domainsOfInterest = [
    "<INSERT>","<KEYWORDS>","<HERE>"
]

apikey = "<INSERTAPIKEY>"
parameters = {"accept": "application/json", "x-Apikey": apikey}
jarmList = []  #listofJARMS to be used later
yesterday = datetime.datetime.now() - timedelta(1)
yesterday = datetime.datetime.strftime(yesterday, '%Y-%m-%d')
yesterday = "2023-01-01" #you can comment this out to provide a specific "since" date!

for domain in domainsOfInterest:
    print(
        "Checking newly registered domains from {} with the phrase {}".format(
            yesterday, domain))
    url = "https://www.virustotal.com/api/v3/intelligence/search?query="
    query = "entity:domain domain:" + domain + " creation_date:" + yesterday + "+ p:1+"
    encodeQuery = urllib.parse.quote(query)  #gotta base64 encode the query
    url = url + encodeQuery

    req = requests.get(url, headers=parameters)
    jsonResp = req.json()
    # json_formatted_str = json.dumps(jsonResp, indent=2)
    # print(json_formatted_str)
    toot = jsonResp.get("data", [])
    if (len(toot) == 0): continue
    else:
        myFile = open("domainsOfInterest.csv", mode="a+")
        print(
            "Domain,JARM,CreationDate,Harmless,Suspicious,Malicious,DomainMimicked",
            file=myFile)
        for i in range(len(toot)):
            id = jsonResp.get("data", [])[i].get("id")
            jarm = jsonResp.get("data", [])[i].get("attributes",
                                                   {}).get("jarm")
            jarmList.append(jarm)
            creationDate = jsonResp.get("data",
                                        [])[i].get("attributes",
                                                   {}).get("creation_date")
            dt = datetime.datetime.fromtimestamp(creationDate)
            stats = jsonResp.get("data",
                                 [])[i].get("attributes",
                                            {}).get("last_analysis_stats")
            print("\t{},{},{},{},{},{}".format(id, jarm, dt, stats["harmless"],
                                                  stats["suspicious"],
                                                  stats["malicious"]))
            print("{},{},{},{},{},{},{}".format(id, jarm, dt,
                                                stats["harmless"],
                                                stats["suspicious"],
                                                stats["malicious"], domain),
                  file=myFile)
    myFile.close()
jarmList = list(dict.fromkeys(jarmList))  #remove dup JARMS

if (len(jarmList) == 0): quit  #if we got nothing, we got nothing to search!
else:
    fileName = "domainsOnAllObservedJarms.csv"
    myFile = open(fileName, mode="a+")
    print("JARM,Domain,CreationDate,Harmless,Suspicious,Malicious",
          file=myFile)
    for i in range(len(jarmList)):
        if jarmList[i] is not None:
            jarm = jarmList[i]
            print("Checking for other domains matching JARM:{}".format(
                jarmList[i]))

            url = "https://www.virustotal.com/api/v3/intelligence/search?query="
            query = "entity:domain jarm:" + jarmList[
                i] + " creation_date:" + yesterday + "+"
            encodeQuery = urllib.parse.quote(query)
            url = url + encodeQuery
            req = requests.get(url, headers=parameters)
            jsonResp = req.json()
            toot = jsonResp.get("data", [])
            for i in range(len(toot)):
                id = jsonResp.get("data", [])[i].get("id")
                creationDate = jsonResp.get("data",
                                            [])[i].get("attributes",
                                                       {}).get("creation_date")
                dt = datetime.datetime.fromtimestamp(creationDate)
                stats = jsonResp.get("data",
                                     [])[i].get("attributes",
                                                {}).get("last_analysis_stats")
                print("\t{},{},{},{},{}".format(id, dt, stats["harmless"],stats["suspicious"], stats["malicious"]))
                print("{},{},{},{},{},{}".format(jarm, id, dt,
                                                 stats["harmless"],
                                                 stats["suspicious"],
                                                 stats["malicious"]),
                      file=myFile)
    myFile.close()
