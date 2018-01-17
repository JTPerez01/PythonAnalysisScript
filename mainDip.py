# Is the hash function overloaded in both VT and Malwares
import requests
import hashlib
from tkinter import *


#########################TO DO LIST###################################################
# Add a gui
# Research the ability to drag and drop
# Add md5 hashing
# Add report writing, complete with link
# Add support for URL search with phishing

########################Malicious File Detection######################################


# add error protection
# Malwares
def malwares():
    params = {'api_key': '2343F1B952B883187CCE5BF73A81681E698774C5BC2B15E9AD6DC2AB1DC83062', 'hash':
        '94EAC5559220793377C3F3B791AA81D853DEEE34D21467D70799A32EB8D4BD51'}
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
        print("Error: Check Code For Integrity")
    print("\n")


# VirusTotal
def virustotal():
    params = {'apikey': '312cd916423489df57dd96f8d374618d6f7759ebf484558f2c30ad2337406cad',
              'resource': '94EAC5559220793377C3F3B791AA81D853DEEE34D21467D70799A32EB8D4BD51'}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    json_response2 = response.json()
    print("The Number Of Positive Match Detections On VirusTotal: " + str(json_response2["positives"]))


########################REPORT#########################################################
def urlreport():
    pass

def filereport():
    malwares()
    virustotal()

if __name__ == '__main__':
    # add tkinter buttons to accept url or choose file
    root = Tk()
    root.title("CenterPoint Diagnostic Information Program")
    root.minsize(width=200,height=100)
    #input with button for urlreport
    e = Entry(root)
    e.pack(side='right')
    e.focus_set()

    b = Button(root, text='Get URL Report', command=None)
    b.pack(side='right')

    e = Entry(root)
    e.pack(side='right')
    e.focus_set()

    b = Button(root, text='Get File Report', command=None)
    b.pack(side='right')

    root.mainloop()

    # on url click set urlarg = True
    # on file drop set filearg = True
    urlarg = False
    filearg = False

    filearg = True
    if (urlarg):
        urlreport()
    if (filearg):
        filereport()