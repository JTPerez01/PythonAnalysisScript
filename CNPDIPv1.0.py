#########################NEED TO KNOW################################################
# Most of these API keys have rate limited queries (usually a maximum of 1 every 2 seconds
# So the program will fail If you switch from hash query to url query really fast
# this is because in both instances VirusTotal is used

import hashlib
from tkinter import *
from tkinter import filedialog
import urllib
import json
import base64
import time
import requests
from requests.auth import HTTPBasicAuth

# Is the hash function overloaded in both VT and Malwares
import servicenow


#########################TO DO LIST###################################################
# Add a gui - DONE
# Research the ability to drag and drop
# Add md5 hashing - DONE with SHA256
# Add report writing, complete with link
# Add support for URL search with phishing - DONE
# Get and display a screenshot - Applied for API key - WORKIN ON
# Add multithreading for the requests and then ask for results later?
# Mesh with PySide for license properties?
# Add outlook Suspicious Folder Scan
# Is there a way to convert the outlook safelink into regular link?

########################API KEYS######################################################
# VirusTotal.com = 312cd916423489df57dd96f8d374618d6f7759ebf484558f2c30ad2337406cad
# Malwares.com = 2343F1B952B883187CCE5BF73A81681E698774C5BC2B15E9AD6DC2AB1DC83062
# Urlscan.io = 292eb904-b5c3-4c56-be26-06aebd73fae8
########################Malicious File Detection######################################


# add error protection

# Malwares file search based on hash
def malwaresfile(passedhash):
    params = {'api_key': '2343F1B952B883187CCE5BF73A81681E698774C5BC2B15E9AD6DC2AB1DC83062', 'hash':
        passedhash}
    response = requests.get('https://www.malwares.com/api/v2/file/behaviorinfo', params=params, verify=False)
    json_response = response.json()
    if (json_response['result_code'] == 0):
        print("There is no data on this hash from Malwares")
    else:
        print("The Security Level From Malwares is: " + str(json_response["security_level"]))
        if (json_response["security_level"] == 3):
            print("This Is Declared As Severe Malicious\n")
        elif (json_response["security_level"] == 2):
            print("This Is Declared As Moderately Malicious\n")
        elif (json_response["security_level"] == 1):
            print("This Is No Detetction\n")
        else:
            print("Error: Check Code For Integrity\n")


# Virus Total file search based on hash
def virustotalfile(passedhash):
    params = {'apikey': '312cd916423489df57dd96f8d374618d6f7759ebf484558f2c30ad2337406cad',
              'resource': passedhash}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, verify=False)
    json_response2 = response.json()
    print("The Number Of Positive Match Detections On VirusTotal: " + str(json_response2["positives"]))

    # Virus Total url search


def virustotalurl(passedurl):
    params = {'apikey': '312cd916423489df57dd96f8d374618d6f7759ebf484558f2c30ad2337406cad', 'url': passedurl}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params, verify=False)
    json_response = response.json()
    params = {'apikey': '312cd916423489df57dd96f8d374618d6f7759ebf484558f2c30ad2337406cad',
              'resource': str(json_response['scan_id'])}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
                             params=params, verify=False)
    json_response = response.json()
    print(json_response)
    result1 = ("VirusTotal URL Positives: " + str(json_response['positives']) + "\nLink Of Report: " + str(
        json_response['permalink']))
    return (str(result1))


# Urlscan.io url search remember to aquire the image
def scaniourl(passedurl):
    headers = {'Content-Type': 'application/json', 'API-Key': '292eb904-b5c3-4c56-be26-06aebd73fae8'}
    params = {"url": passedurl, "public": "on"}
    json_response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=params, verify=False)
    return (str(json_response))


# SHA256 hashing of file in chunks
def hashthenfilesearch():
    root.filename = filedialog.askopenfilename(initialdir='C:\\', title="Hash This File")
    fname = root.filename
    hash_sha256 = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    filehash = hash_sha256.hexdigest()
    print("File was hashed to(sha256): " + str(filehash) + " passing to file analysis.")
    filereport(filehash)


# Safelink passed to program
def safelinkpassed():
    data = e4.get()
    url_parts = str(data).split("?")[1]
    params = url_parts.split("&")
    target_url = None
    for x in range(int(len(params))):
        namval = params[x].split("=")
        if (namval[0] == "url"):
            target_url = namval[1]
    decode_url = urllib.parse.unquote(target_url)
    urlreport(decode_url)

def getScreenshot(urlpassed):
    #key = beginCapture("http://www.amazon.com", "1200x800", "true", "firefox", "true")
    url = urlpassed
    fullpage = True
    viewport = "1200x800"
    webdriver = "firefox"
    javascript = True
    timeout = 30
    tCounter = 0
    tCountIncr = 3


    serverUrl = "https://api.screenshotapi.io/capture"
    print('Sending request: ' + url)
    headers = {'apikey': 'b00e28cf-6204-44f0-af6f-b7b0b48f6750'}
    params = {'url': urllib.parse.unquote(url).encode('utf8'), 'viewport': viewport, 'fullpage': fullpage,
              'webdriver': webdriver, 'javascript': javascript}
    result = requests.post(serverUrl, data=params, headers=headers, verify=False)
    print(result.text)
    # {"status":"ready","key":"f469a4c54b4852b046c6f210935679ae"}
    json_results = json.loads(result.text)
    resultkey = json_results['key']




    while True:
        url = 'https://api.screenshotapi.io/retrieve'
        headers = {'apikey': 'b00e28cf-6204-44f0-af6f-b7b0b48f6750'}
        params = {'key': resultkey}
        print('Trying to retrieve: ' + url)
        result = requests.get(url, params=params, headers=headers, verify=False)
        # {"status":"ready","imageUrl":"http://screenshotapi.s3.amazonaws.com/captures/f469a4c54b4852b046c6f210935679ae.png"}
        json_results = json.loads(result.text)
        if json_results["status"] == "ready":
            print('Downloading image: ' + json_results["imageUrl"])
            image_result = requests.get(json_results["imageUrl"])
            imageRes = json_results["imageUrl"]

            successresult = {'success': True, 'bytes': image_result.content}
        else:
            successresult = {'success': False}
        if successresult["success"]:
            print("Saving screenshot to: downloaded_screenshot.png" + resultkey)
            #open('downloaded_screenshot.png', 'wb').write(result['bytes'])
            break
        else:
            tCounter += tCountIncr
            print("Screenshot not yet ready.. waiting for: " + str(tCountIncr) + " seconds.")
            time.sleep(tCountIncr)
            if tCounter > timeout:
                print("Timed out while downloading: " + resultkey)
                break
    return imageRes

def sneakpeak(urlpassed):
    popup = Toplevel(root)
    Grid.rowconfigure(popup, 0, weight=1)
    Grid.columnconfigure(popup, 0, weight=1)
    popup.title("DIP Sneak Peak")
    # a little more than width and height of image
    w = 1200
    h = 800
    x = 300
    y = 300
    # use width x height + x_offset + y_offset (no spaces!)
    popup.geometry("%dx%d+%d+%d" % (w, h, x, y))
    # this GIF picture previously downloaded to tinypic.com
    image_url = urlpassed
    image_byt = urllib.request.urlopen(image_url).read()
    image_b64 = base64.encodestring(image_byt)
    photo = PhotoImage(data=image_b64)
    # create a white canvas
    cv = Canvas(popup, bg='white')
    cv.grid(row=0, column=0, sticky=N + S + E + W)
    # put the image on the canvas with
    # create_image(xpos, ypos, image, anchor)
    cv.create_image(0, 0, image=photo, anchor="nw")
    popup.mainloop()

########################REPORT#########################################################
def urlreport(urlpassed=None):
    if (urlpassed == None):
        data = e.get()
    else:
        data = urlpassed
    print("Passing URL: " + str(data))
    report = ""
    report += virustotalurl(str(data))
    report += "\n"
    report += scaniourl(str(data))
    print(report)
    #run the screenshot capture
    screenshotlink = getScreenshot(data)
    #run the popup nugget
    sneakpeak(screenshotlink)
    #username = usr.get()
    #password = pw.get()
    #caller_id = caller.get()
    #report += "\nLink at: " + data
    #servicenow.ticketgenerate(username, password, caller_id, report)


def filereport(filehash=None):
    if (filehash == None):
        data = e2.get()
        print("Passing HASH: " + str(data))
    else:
        data = filehash
    malwaresfile(data)
    virustotalfile(data)


def ticketgenerate(username, password, caller_id, description):
    proxies = {
        "http": "http://127.0.0.1:8888",
        "https": "https://127.0.0.1:8888",
    }

    auth = HTTPBasicAuth(str(username), str(password))
    uri = "https://centerpointenergy.service-now.com/incident.do?JSONv2"

    # define http headers for request
    headers = {
        "Accept": "application/json;charset=utf-8",
        "Content-Type": "application/json"
    }

    # define payload for request, note we are passing the sysparm_action variable in the body of the request
    # http://wiki.servicenow.com/index.php?title=JSONv2_Web_Service#insert
    # the person who is calling and being assigned to must already be in the system
    payload = {
        'sysparm_action': 'insert',
        'category': 'Security - Cybersecurity',
        'subcategory': 'Phishing / Spam Alert',
        'affected_user': caller_id,
        'impact': '3',
        'urgency': '3',
        'work_notes': 'TBD',
        'comments': 'TBD',
        'description': description,
        'short_description': 'Phishing - User Reported (DIP)',
        'contact_type': 'Self-service',
        'user_id': username,
        'caller': caller_id,
        'caller_id': caller_id,
        'assigned_to': caller_id,
        'state': 'awaiting info',
        'assignment_group': 'Security Operations Center'
    }

    r = requests.post(url=uri, data=json.dumps(payload), auth=auth, verify=False, headers=headers)
    content = r.json()
    assert (r.status_code == 200)
    print("Response Status Code: " + str(r.status_code))
    print("Response JSON Content: " + str(content))
    if str(r.status_code) == "200":
        return True


if __name__ == '__main__':
    # add tkinter buttons to accept url or choose file
    root = Tk()
    root.title("CenterPoint Diagnostic Information Program")
    root.minsize(width=300, height=600)
    # input with button for urlreport
    l1 = Label(root, text="CNP Username")
    l1.grid(row=0, column=0)
    usr = Entry(root, width=20)
    usr.grid(row=0, column=1)

    l2 = Label(root, text="CNP Password")
    l2.grid(row=1, column=0)
    pw = Entry(root, show="*", width=20)
    pw.grid(row=1, column=1)

    l3 = Label(root, text="ServiceNow Caller ID")
    l3.grid(row=2, column=0)
    caller = Entry(root, width=20)
    caller.grid(row=2, column=1)

    e = Entry(root, width=180)
    e.grid(row=3, column=1)

    b = Button(root, text='Get URL Report', command=urlreport, font="System")
    b.grid(row=3, column=0)

    e2 = Entry(root, width=180)
    e2.grid(row=4, column=1)

    b2 = Button(root, text='Get File Report', command=filereport, font="System")
    b2.grid(row=4, column=0)

    b3 = Button(root, text='Upload File', command=hashthenfilesearch, font="System")
    b3.grid(row=5, columnspan=2, sticky='NSEW')

    e4 = Entry(root, width=180)
    e4.grid(row=6, column=1)

    b4 = Button(root, text='Safelink decode/analysis', command=safelinkpassed, font="System")
    b4.grid(row=6, column=0)
    label = Label(root, text="Never Forget").grid(row=7, columnspan=2)

    root.mainloop()
