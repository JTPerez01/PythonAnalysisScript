# Is the hash function overloaded in both VT and Malwares
import requests
import hashlib
from tkinter import *
from tkinter import filedialog


#########################TO DO LIST###################################################
# Add a gui - DONE
# Research the ability to drag and drop
# Add md5 hashing
# Add report writing, complete with link
# Add support for URL search with phishing - DONE

########################Malicious File Detection######################################


# add error protection
# Malwares
def malwaresfile(passedhash):
    params = {'api_key': '2343F1B952B883187CCE5BF73A81681E698774C5BC2B15E9AD6DC2AB1DC83062', 'hash':
        passedhash}
    response = requests.get('https://www.malwares.com/api/v2/file/behaviorinfo', params=params)
    json_response = response.json()
    print ("The Security Level From Malwares is: " + str(json_response["security_level"]))
    if (json_response["security_level"] == 3):
        print("This Is Declared As Severe Malicious\n")
    elif (json_response["security_level"] == 2):
        print("This Is Declared As Moderately Malicious\n")
    elif (json_response["security_level"] == 1):
        print("This Is No Detetction\n")
    else:
        print("Error: Check Code For Integrity\n")


def virustotalfile(passedhash):
    params = {'apikey': '312cd916423489df57dd96f8d374618d6f7759ebf484558f2c30ad2337406cad',
              'resource': passedhash}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    json_response2 = response.json()
    print("The Number Of Positive Match Detections On VirusTotal: " + str(json_response2["positives"]))

def virustotalurl():
    params = {'apikey': '312cd916423489df57dd96f8d374618d6f7759ebf484558f2c30ad2337406cad', 'url': 'http://www.virustotal.com'}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
    json_response = response.json()
    params = {'apikey': '312cd916423489df57dd96f8d374618d6f7759ebf484558f2c30ad2337406cad', 'resource': str(json_response['scan_id'])}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
                             params=params)
    json_response = response.json()
    print ("VirusTotal URL Positives: " + str(json_response['positives']))

def hashthenfilesearch():
    root.filename = filedialog.askopenfilename(initialdir = 'C:\\', title = "Hash This File")
    print (root.filename)



########################REPORT#########################################################
def urlreport():
    data = e.get()
    print("Passing URL: " + str(data))
    virustotalurl()

def filereport():
    data = e2.get()
    print("Passing HASH: " + str(data))
    malwaresfile(data)
    virustotalfile(data)

if __name__ == '__main__':
    # add tkinter buttons to accept url or choose file
    root = Tk()
    root.title("CenterPoint Diagnostic Information Program")
    root.minsize(width=200,height=100)
    #input with button for urlreport
    e = Entry(root)
    e.pack(side='right')
    e.focus_set()

    b = Button(root, text='Get URL Report', command=urlreport)
    b.pack(side='right')

    e2 = Entry(root)
    e2.pack(side='right')
    e2.focus_set()

    b2 = Button(root, text='Get File Report', command=filereport)
    b2.pack(side='right')

    b3 = Button(root, text='Upoad File', command=hashthenfilesearch)
    b3.pack(side='right')

    root.mainloop()
