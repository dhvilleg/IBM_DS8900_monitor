import http.client
import ssl
import json
from datetime import datetime
from urllib.parse import urlencode

   
def create_https_connection(host):
    return http.client.HTTPSConnection(host, context = ssl._create_unverified_context())


def get_token_from_connection(host, connection, username, password):
    try:
        headers = {'Content-type': 'application/json'}
        
        body = {"request":{"params":{"username":"{}".format(username),"password":"{}".format(password)}}}
        json_data = json.dumps(body)
        
        connection.request("POST", "/api/v1/tokens", json_data, headers)
        response = connection.getresponse()
        json_token_response = json.loads(response.read().decode())["token"]["token"]
        connection.close()
        
        return json_token_response
    
    except Exception as error:
        print("an error was raised trying to get token file {}".format(error))
        write_events_to_file(get_date_time("%d-%m-%Y-%H:%M:%S"), "Connection Error", host,error)
        connection.close()


def get_events_from_stg(connection, token, severity, event_time):
    try:
        header = {"Content-type":"application/json", "X-Auth-Token":"{}".format(token)}
        baseurl="/api/v1/events?severity={}&before={}".format(severity, event_time)
        connection.request("GET", baseurl, headers=header)

        response = connection.getresponse()
        print("Status: {} and reason: {}".format(response.status, response.reason))
        json_events = json.loads(response.read().decode())
       
        connection.close()
        
        return json_events
    
    except Exception as error:
        print("an error was raised, closing http connection with error {}".format(error))
        connection.close()
        

def get_date_time(format_time):
    now = datetime.now()
    date_formated = now.strftime(format_time)
    return str(date_formated)


def write_events_to_file(format_time, alert_type, alerted_host, events_list):
    if type(events_list) is list:
        event_file = open("SpectrumControlLOG.txt", "a")  # append mode
        if len(events_list) > 0:
            for i in events_list:
                if i["description"] == "":
                    pass
                else:
                    event_file.write("\n{};{};{};{}".format(format_time, alert_type, alerted_host, i["description"]))
        
        event_file.close()
        
    else:
        event_file = open("SpectrumControlLOG.txt", "a")  # append mode
        event_file.write("\n{};{};{};{}".format(format_time, alert_type, alerted_host, events_list))
        event_file.close()
    

def execute_stg_mon(event_type):
    storage_file = open("storage.conf")
    
    for stg_list in storage_file:
        stg_name = stg_list.split(",")[1]
        stg_ip = stg_list.split(",")[2]
        stg_user = stg_list.split(",")[3]
        stg_passwd = stg_list.split(",")[4]
    
        connection = create_https_connection(stg_ip)
        token = get_token_from_connection(stg_name, connection,stg_user,stg_passwd)
        #17-06-2023-06:39:10
        events_list = []
        try:
            json_events = get_events_from_stg(connection, token, event_type, get_date_time("%Y-%m-%dT%H:%M:%S-0700"))

            for item in json_events["data"]["events"]:
                event_details = {"description":None}
                event_details['description'] = item['description']
                events_list.append(event_details)

            write_events_to_file(get_date_time("%d-%m-%Y-%H:%M:%S"), "Storage System", stg_name, events_list)
        except Exception as error:
            print("an error ocured trying to parse json object: {}".format(error))


if __name__ == '__main__':
    execute_stg_mon("warning")
    execute_stg_mon("error")
        