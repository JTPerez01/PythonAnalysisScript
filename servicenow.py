# Attempt to add support via the ServiceNow API
#####################TO DO#####################
# Add ability to create a ticket and populate fields 
# Take input for the Caller (will change)
  Thiss will populate User ID with CNP ID, add the Afected User as self and change Location to EC/DC
# Set Priority level (at the discresion of the caller)
# Assign the team Security - Cybersecurity (will always be)
# Assign to proper incident label (Can get from main program choice)
# Assign to On-Call (will change)
# Populate work notes with the report generated from the AnalysisScript
# 

import requests
import json
