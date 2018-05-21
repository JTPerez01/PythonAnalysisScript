#########################NEED TO KNOW################################################
# Most of these API keys have rate limited queries (usually a maximum of 1 every 2 seconds
# So the program will fail If you switch from hash query to url query really fast
# this is because in both instances VirusTotal is used69 gto
# https://docs.servicenow.com/bundle/geneva-servicenow-platform/page/integrate/inbound_rest/reference/r_AttachmentAPI-POST.html
# Add the module to attach the .png, that would be wicked-pissah
import hashlib
import time
from tkinter import *
from tkinter import filedialog
import urllib
import json
import base64
import time
import requests
from requests.auth import HTTPBasicAuth



########################API KEYS######################################################
virustotalapi = '312cd916423489df57dd96f8d374618d6f7759ebf484558f2c30ad2337406cad'
malwaresapi = '2343F1B952B883187CCE5BF73A81681E698774C5BC2B15E9AD6DC2AB1DC83062'
urlscanapi = '292eb904-b5c3-4c56-be26-06aebd73fae8'
screenshotapi = 'b00e28cf-6204-44f0-af6f-b7b0b48f6750'
########################Malicious File Detection######################################


# add error protection

# Malwares file search based on hash NOT WORKING!!!!!!!!!!!!!!!!!!
def malwaresfile(passedhash):
    params = {'api_key': malwaresapi, 'Hash':
        passedhash}
    response = requests.get('https://www.malwares.com/api/v2/file/mwsinfo', params=params, verify=False)
    json_response = response.json()
    reportreturned = ""
    print (json_response)
    if ((json_response['result_code']) == 0):
        reportreturned += "There is no data on this hash from Malwares"
    else:
        reportreturned += "The Security Level From Malwares is: " + str(json_response["security_level"]) + "\n"
        if (json_response["security_level"] == 3):
            reportreturned += "This Is Declared As Severe Malicious\n"
        elif (json_response["security_level"] == 2):
            reportreturned += "This Is Declared As Moderately Malicious\n"
        elif (json_response["security_level"] == 1):
            reportreturned += "This Is No Detetction\n"
        else:
            reportreturned += "Error: Check Code For Integrity\n"
    return reportreturned


# Virus Total file search based on hash
def virustotalfile(passedhash):
    params = {'apikey': virustotalapi,
              'resource': passedhash}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, verify=False)
    json_response2 = response.json()
    print (json_response2)
    returnedreport = ""
    returnedreport += "The Number Of Positive Match Detections On VirusTotal: " + str(json_response2["positives"])
    return returnedreport


# Virus Total url search
def virustotalurl(passedurl):
    params = {'apikey': virustotalapi, 'url': passedurl}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params, verify=False)
    json_response = response.json()
    print (json_response)
    if (json_response['response_code']==-1):
        errorscreenshot(passedurl)
    params = {'apikey': virustotalapi,'resource': str(json_response['scan_id'])}
    emptyList = []
    while True:
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report',
                                 params=params, verify=False)
        json_response = response.json()
        print(json_response)
        if (json_response == emptyList) or json_response['response_code'] == 0 :
            time.sleep(8)
        else:
            break

    print(json_response)
    result1 = ("VirusTotal URL Positives: " + str(json_response['positives']) + "\nLink Of Report: " + str(
        json_response['permalink']))
    return (str(result1))


# Urlscan.io url search remember to aquire the image
def scaniourl(passedurl):
    headers = {'Content-Type': 'application/json', 'API-Key': urlscanapi}
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
    e4.delete(0, END)
    try:
        url_parts = str(data).split("?")[1]
    except IndexError:
        safelinkerror(data)
    params = url_parts.split("&")
    target_url = None
    for x in range(int(len(params))):
        namval = params[x].split("=")
        if (namval[0] == "url"):
            target_url = namval[1]
    decode_url = urllib.parse.unquote(target_url)
    urlreport(decode_url)


def safelinkerror(data):
    errorrootsl = Toplevel(root)
    Grid.rowconfigure(errorrootsl, 0, weight=1)
    Grid.columnconfigure(errorrootsl, 0, weight=1)
    errorrootsl.title("DIP Error")
    w = 200
    h = 100
    x = 50
    y = 50
    errorrootsl.geometry("%dx%d+%d+%d" % (w, h, x, y))
    errorlabel = Label(errorrootsl, text="Error decoding safelink: Check Format\nPassed SL: " + data)
    errorlabel.grid(row=0, column=0, sticky='NSEW')


def getScreenshot(urlpassed):
    # key = beginCapture("http://www.amazon.com", "1200x800", "true", "firefox", "true")
    url = urlpassed
    fullpage = True
    viewport = "1200x800"
    webdriver = "firefox"
    javascript = True
    timeout = 40
    tCounter = 0
    tCountIncr = 4

    serverUrl = "https://api.screenshotapi.io/capture"
    print('Sending request: ' + url)
    headers = {'apikey': screenshotapi}
    params = {'url': urllib.parse.unquote(url).encode('utf8'), 'viewport': viewport, 'fullpage': fullpage,
              'webdriver': webdriver, 'javascript': javascript}
    result = requests.post(serverUrl, data=params, headers=headers, verify=False)
    print(result.text)
    # {"status":"ready","key":"f469a4c54b4852b046c6f210935679ae"}
    json_results = json.loads(result.text)
    resultkey = json_results['key']

    while True:
        urlr = 'https://api.screenshotapi.io/retrieve'
        headers = {'apikey': screenshotapi}
        params = {'key': resultkey}
        print('Trying to retrieve: ' + url)
        result = requests.get(urlr, params=params, headers=headers, verify=False)
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
            # open('downloaded_screenshot.png', 'wb').write(result['bytes'])
            break
        else:
            tCounter += tCountIncr
            print("Screenshot not yet ready.. waiting for: " + str(tCountIncr) + " seconds.")
            time.sleep(tCountIncr)
            if tCounter > timeout:
                print("Timed out while downloading: " + resultkey)
                #Might want to add an option to errorscreenshot that would allow more time to attach.
                errorscreenshot(url)
                break

    return [imageRes, resultkey]


def errorscreenshot(url):
    errorroot = Toplevel(root)
    Grid.rowconfigure(errorroot, 0, weight = 1)
    Grid.columnconfigure(errorroot, 0, weight = 1)
    errorroot.title("DIP Error")
    w = 200
    h = 100
    x = 50
    y = 50
    errorroot.geometry("%dx%d+%d+%d" % (w, h, x, y))
    errorlabel = Label(errorroot, text="Screenshot not generated.\nDomain may not exist.\n"+url)
    errorlabel.grid(row=0, column=0, sticky='NSEW')


#sneak peak add buttons to copy malicous email text, copy non malicious text
def sneakpeak(urlpassed, report):
    sneakreport = report
    popup = Toplevel(root)
    Grid.rowconfigure(popup, 0, weight=10)
    Grid.rowconfigure(popup, 1, weight=1)
    Grid.rowconfigure(popup, 2, weight=1)
    Grid.rowconfigure(popup, 3, weight=2)
    Grid.rowconfigure(popup, 4, weight=3)
    Grid.columnconfigure(popup, 0, weight=10)
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
    image_b64 = base64.encodebytes(image_byt)
    photo = PhotoImage(data=image_b64)
    # create a white canvas
    cv = Canvas(popup, bg='white')
    cv.grid(row=0, column=0, sticky=N + S + E + W)
    # put the image on the canvas with
    # create_image(xpos, ypos, image, anchor)
    cv.create_image(0, 0, image=photo, anchor="nw")

    reportlabel = Label(popup, text=sneakreport)
    reportlabel.grid(row=1, column=0)

    copymalicious = Button(popup, text="Copy Malicious Response.", command=copym)
    copymalicious.grid(row=2, column=0)

    copynonmalicious = Button(popup, text="Copy Non-Malicious Reponse.", command=copynm)
    copynonmalicious.grid(row=3, column=0)

    popup.mainloop()

def copym():
    r = Tk()
    r.withdraw()
    r.clipboard_clear()
    r.clipboard_append('Hello XXXX,\n\n\tIt appears that this email was malicious. Please do not open any links or attachments associated with the message.  Please delete the message from your Inbox, Sent Items and Deleted Items.\n\nSincerely,')
    r.update()  # now it stays on the clipboard after the window is closed
    r.mainloop()


def copynm():
    r = Tk()
    r.withdraw()
    r.clipboard_clear()
    r.clipboard_append('Hello XXXX,\n\n\tIt appears that this email is not malicious. However, we advise to delete emails from unknown parties or suspicious domains. If this party is unknown, do not open any links or attachments associated with the message.  Please delete message from your Inbox, Sent Items and Deleted Items.\n\nSincerely,')
    r.update()  # now it stays on the clipboard after the window is closed
    r.mainloop()



#####################ATTACH STUFF TO TICKET############################################
def attachscreenshot(screenshotlink, screenshotkey, username, password, sysId):
    image_url = screenshotlink
    sysId = sysId
    imageId = screenshotkey + '.png'
    image_byt = urllib.request.urlopen(image_url).read()
    # Set the request parameters
    url = 'https://website.service-now.com/api/now/attachment/file?table_name=incident&table_sys_id=' + sysId + '&file_name=' + imageId

    # Specify the file To send. When specifying fles to send make sure you specify the path to the file, in
    # this example the file was located in the same directory as the python script being executed.
    data = image_byt

    # Eg. User name="admin", Password="admin" for this code sample.
    user = username
    pwd = password

    # Set proper headers
    headers = {"Content-Type": "image/png", "Accept": "application/json"}

    # Do the HTTP request
    response = requests.post(url, auth=(user, pwd), headers=headers, data=image_byt, verify=False)

    # Check for HTTP codes other than 201
    if response.status_code != 201:
        print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:', response.json())
        exit()

    # Decode the JSON response into a dictionary and use the data
    data = response.json()
    print(data)


def attachfile(username, password, sysId, file):
    # Set the request parameters
    url = 'https://website.service-now.com/api/now/attachment/file?table_name=incident&table_sys_id=' + sysId + '&file_name=' + file

    # Specify the file To send. When specifying fles to send make sure you specify the path to the file, in
    # this example the file was located in the same directory as the python script being executed.
    data = open(file, 'rb').read()

    # Eg. User name="admin", Password="admin" for this code sample.
    user = username
    pwd = password

    # Set proper headers
    headers = {"Content-Type": "*/*", "Accept": "application/json"}

    # Do the HTTP request
    response = requests.post(url, auth=(user, pwd), headers=headers, data=data)

    # Check for HTTP codes other than 201
    if response.status_code != 201:
        print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:', response.json())
        exit()

    # Decode the JSON response into a dictionary and use the data
    data = response.json()
    print(data)

########################REPORT#########################################################
def urlreport(urlpassed=None):
    if (urlpassed == None):
        data = e.get()
        e.delete(0, END)
    else:
        data = urlpassed
    print("Passing URL: " + str(data))
    report = ""
    report += virustotalurl(str(data))
    report += "\n"
    # report += scaniourl(str(data))#not working, who cares
    print(report)
    username = usr.get()
    password = pw.get()
    caller_id = caller.get()
    report += "\nLink at: " + data
    sysId = ticketgenerate(username, password, caller_id, report)
    # run the screenshot capture
    screenshotlink = getScreenshot(data)
    # attach screenshot to ticket
    attachscreenshot(screenshotlink[0], screenshotlink[1], username, password, sysId)
    # run the popup nugget
    sneakpeak(screenshotlink[0], report)


def filereport(filehash=None):
    if (filehash == None):
        data = e2.get()
        e2.delete(0, END)
        print("Passing HASH: " + str(data))
    else:
        data = filehash
    report = ""
    #report += malwaresfile(data) + "\n"
    report += virustotalfile(data)
    username = usr.get()
    password = pw.get()
    caller_id = caller.get()
    sysId = ticketgenerate(username, password, caller_id, report)
    #attachfile()


#######################TICKET GENERATION################################################

def ticketgenerate(username, password, caller_id, description):
    proxies = {
        "http": "http://127.0.0.1:8888",
        "https": "https://127.0.0.1:8888",
    }

    auth = HTTPBasicAuth(str(username), str(password))
    uri = "https://website.service-now.com/incident.do?JSONv2"

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
    resultlist = content['records']
    sysId = resultlist[0]['sys_id']
    print(sysId)
    if str(r.status_code) == "200":
        return sysId


if __name__ == '__main__':
    # add tkinter buttons to accept url or choose file
    root = Tk()
    root.title("website Diagnostic Information Program")
    root.minsize(width=300, height=200)
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

    b4 = Button(root, text='Safelink Decode+Analysis', command=safelinkpassed, font="System")
    b4.grid(row=6, column=0)
    label = Label(root, text="Hot Dog Build").grid(row=7, columnspan=2)

    root.mainloop()
