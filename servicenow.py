# Attempt to add support via the ServiceNow API
#####################TO DO#####################
# Add ability to create a ticket and populate fields 
# Take input for the Caller (will change)
# Thiss will populate User ID with CNP ID, add the Afected User as self and change Location to EC/DC
# Set Priority level (at the discresion of the caller)
# Assign the team Security - Cybersecurity (will always be)
# Assign to proper incident label (Can get from main program choice)
# Assign to On-Call (will change)
# Populate work notes with the report generated from the AnalysisScript
# 

import json
import requests
from requests.auth import HTTPBasicAuth

# using local http proxy to log requests and responses
proxies = {
    "http": "http://127.0.0.1:8888",
    "https": "https://127.0.0.1:8888",
}

auth = HTTPBasicAuth("admin", "Center1!")
uri = "https://dev17860.service-now.com/incident.do?JSONv2"

# define http headers for request
headers = {
    "Accept": "application/json;charset=utf-8",
    "Content-Type": "application/json"
}

# define payload for request, note we are passing the sysparm_action variable in the body of the request
# http://wiki.servicenow.com/index.php?title=JSONv2_Web_Service#insert
#the person who is calling and being assigned to must already be in the system
payload = {
    'sysparm_action': 'insert',
    'category': 'software',
    'impact': '1',
    'urgency': '1',
    'work_notes': 'add work notes',
    'comments': 'add comments',
    'short_description': 'Phishing - User Reported CNPDIP',
    'cmdb_ci': 'Email',
    'caller_id': 'Joshua Perez'
    'assigned_to': 'Joshua Sutfin'
}

r = requests.post(url=uri, data=json.dumps(payload), auth=auth, proxies=proxies, verify=False, headers=headers)
content = r.json()
assert (r.status_code == 200)
print "Response Status Code: " + str(r.status_code)
print "Response JSON Content: " + str(content)
