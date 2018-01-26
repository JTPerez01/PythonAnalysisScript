#########################NEED TO KNOW################################################
#Most of these API keys have rate limited queries (usually a maximum of 1 every 2 seconds
#So the program will fail If you switch from hash query to url query really fast
#this is because in both instances VirusTotal is used

# Is the hash function overloaded in both VT and Malwares
import requests
import hashlib
from tkinter import *
from tkinter import filedialog




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
#VirusTotal.com = 312cd916423489df57dd96f8d374618d6f7759ebf484558f2c30ad2337406cad
#Malwares.com = 2343F1B952B883187CCE5BF73A81681E698774C5BC2B15E9AD6DC2AB1DC83062
#Urlscan.io = 292eb904-b5c3-4c56-be26-06aebd73fae8
########################Malicious File Detection######################################


# add error protection

# Malwares file search based on hash
def malwaresfile(passedhash):
    params = {'api_key': '2343F1B952B883187CCE5BF73A81681E698774C5BC2B15E9AD6DC2AB1DC83062', 'hash':
        passedhash}
    response = requests.get('https://www.malwares.com/api/v2/file/behaviorinfo', params=params)
    json_response = response.json()
    if (json_response['result_code'] == 0):
        print("There is no data on this hash from Malwares")
    else:
        print ("The Security Level From Malwares is: " + str(json_response["security_level"]))
        if (json_response["security_level"] == 3):
            print("This Is Declared As Severe Malicious\n")
        elif (json_response["security_level"] == 2):
            print("This Is Declared As Moderately Malicious\n")
        elif (json_response["security_level"] == 1):
            print("This Is No Detetction\n")
        else:
            print("Error: Check Code For Integrity\n")

            
#Virus Total file search based on hash
def virustotalfile(passedhash):
    params = {'apikey': '312cd916423489df57dd96f8d374618d6f7759ebf484558f2c30ad2337406cad',
              'resource': passedhash}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    json_response2 = response.json()
    print("The Number Of Positive Match Detections On VirusTotal: " + str(json_response2["positives"]))

    
    #Virus Total url search
def virustotalurl(passedurl):
    params = {'apikey': '312cd916423489df57dd96f8d374618d6f7759ebf484558f2c30ad2337406cad', 'url': passedurl}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
    json_response = response.json()
    params = {'apikey': '312cd916423489df57dd96f8d374618d6f7759ebf484558f2c30ad2337406cad', 'resource': str(json_response['scan_id'])}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
                             params=params)
    json_response = response.json()
    print ("VirusTotal URL Positives: " + str(json_response['positives']) +"\nLink Of Report: " + str(json_response['permalink']))
  

#Urlscan.io url search remember to aquire the image
def scaniourl(passedurl):
    headers = { 'Content-Type': 'application/json', 'API-Key': '292eb904-b5c3-4c56-be26-06aebd73fae8'}
    params = {"url": passedurl, "public": "on"}
    json_response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=params)
    print (str(json_response))
 

    
#SHA256 hashing of file in chunks    
def hashthenfilesearch():
    root.filename = filedialog.askopenfilename(initialdir = 'C:\\', title = "Hash This File")
    fname = root.filename
    hash_sha256 = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    filehash = hash_sha256.hexdigest()
    print("File was hashed to(md5): " + str(filehash) + " passing to file analysis.")
    filereport(filehash)


########################REPORT#########################################################
def urlreport():
    data = e.get()
    print("Passing URL: " + str(data))
    virustotalurl(data)

def filereport(filehash):
    if (filehash == None):
        data = e2.get()
        print("Passing HASH: " + str(data))
    else:
        data = filehash
    malwaresfile(data)
    virustotalfile(data)
    
    
def main():
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

    label = Label(root, text="hey lol")
    label.pack(side='bottom')

    root.mainloop()
    

if __name__ == '__main__':
    main()
