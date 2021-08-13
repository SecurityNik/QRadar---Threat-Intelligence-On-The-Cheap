# QRadar---Threat-Intelligence-On-The-Cheap
# SecurityNikThreatIntel.py
# Download a list of suspected malicious IPs and Domains. Create a QRadar Reference Set. Search Your Environment For Malicious IPs

Recently I needed to address a little challenge with getting threat intelligence (known malicious IPs and or Domains) into QRadar, so that I could use that information in a proactive manner. What I ended up doing was, from a list of publicly available known blacklist (of both domains and IPs) I gathered this information to incorporate it into QRadar Reference Set. Obviously, an alternative to what I've done is to purchase IBM X-Force, Norse Darklist or some other dark list. However, if you are looking at addressing this need on a small budget ($0000.00), my solution is a good place for you to start.

So what does the solution do? Basically the following.
1. From a list of published blacklisted IPs download all and create one file
2. From a list of published blacklisted DNS download all and create one file.
3. Check QRadar to see if a reference set exists with name "SecurityNik_DarkList_IP", if none exists create it
4. Upload the compiled file of IPs to the Reference Set
5 Check QRadar to see if a reference set exists with name "SecurityNik_DarkList_DNS", if none exist create
6.Upload the compiled file of DNS to the Reference Set
‎
Once the script runs for the first time, you will need to create 2 rules. One checks your events and flows for the source or destination IP in the reference set and the other checks for the domain name in events.

I spent the time to develop this to address a need. I'm sharing it with this forum because I know someone else may have had (or is having) similar concerns like I had. Feel free to modify the script as you wish, but please leave my credit.

The script and information on how to create the rules,  etc can be found on my blog at securitynik.blogspot.com.

Sorry that I have to sent you to my blog to get it. However, there is additional information there on creating the rules.

Feel free to reach out to me if you have any questions, concerns and or comments.

P.S. Point to note is the quality of these list are dependent on the people who publish them. I give no warranty or am I vouching for these lists. These IPs and or domains should be used as a starting point of your investigation and not the ultimate decision as to whether something good or bad has happened.

If you need the code only that ‎can be found here‎:
https://drive.google.com/file/d/0B0qDfJ30s2I9ajRXTHh2UTItbkk/view?usp=sharing

‎Enjoy!!
