# bobber
A Python 3 reverse proxy designed to secure phishing exercises via one-time-use tokens, based on the idea behind [bashexplode's *otu-plz* application](https://github.com/bashexplode/otu-plz). 

This script was developed for educational purposes to aid with adversary emulation exercises, and should not be used to assist in malicious or illegal purposes.

---

# Introduction
Bobber is a tool designed primarily to serve three purposes:
1. Secure phishing campaigns via enforcing a maximum of one visit to the web application per user ID
2. Accomplish the above while requiring as little integration work with a phishing app or cloned site as possible
3. Serve legitimate content when incoming traffic is not meant for the phishing campaign to throw off defenders

This project is a Proof-of-Concept written in Flask and leveraging SQLite3. As it is a Proof-of-Concept, there is currently no automation provided for integration with Apache2, Nginx, or IIS although it is being considered for future commits.

---

# Installation

The installation process is fairly straightforward. The below steps should get bobber up and running:
1. Using your system's package manager, install `sqlite3`
2. Using Python 3, run `pip3 install -r requirements.txt` to install dependencies

---

# Configuration
Bobber runs on 7 different configuration parameters; however, for a Proof-of-Concept the default values should work fine for the last two.

Parameter  |  Example | Description 
-------------- | ------------- | -----------
**TOKENS** | /path/to/my/tokenfile | This should be an absolute path (or relative path to bobber.py) to a file containing a list of IDs (one per line) that should be allowed to access the phishing application
**REDIRECT_DOMAIN** | https://mybobberserver.com:8443 | This should be a full URL to the bobber application, as it will be used as a substitute for relative links
**PHSIHAPP_DOMAIN** | https://mycustomapplication.com | This should be a full URL to the site hosting your custom app
**SPOOFED_DOMAIN** | https://some-redirected-site.com | This should be a full URL to the a site whose content should be served in place of PHISHAPP_DOMAIN
**TOKEN_DELIMTER** | uid | This should be the value of the GET parameter being used to track custom application usage (e.g. mycustomapplication.com?**uid**=12345)
**TIMEOUT_LENGTH** | 900 | This should be amount of time (15 minutes by default) in seconds that a user should be able to interact with the web application before losing access to the phishing domain.
**BOBBER_DB** and **BOBBER_LOCATION** | See description | Bobber (by default) will create a bobber.[timestamp].db file in the same directory as the bobber.py file. However, a custom bobber DB file can be used by inserting the full path into *BOBBER_LOCATION* and uncommenting the BOBBER_DB line with the BOBBER_LOCATION parameter.

**Note:** The bobber DB should have the following naming convention: *bobber.arbitrarytext.db*

---

# Running bobber

If all the parameters are set, bobber can be run with the below command
```
python3 bobber.py
```

# Reporting

A CSV file can be generated from a bobber DB by using `report.sh` and passing the bobber DB file as a parameter:
```
chmod +x report.sh
./report.sh bobber.[timestamp].db
```
report.sh will output a CSV file named after the middle of the DB content.

For example, if the bobber DB is named *bobber.example.db*, its contents will be put into an *example.csv* CSV file.

---

# How does it work?
## Summary
`bobber.py` is a Python Flask application that serves as a reverse proxy which serves content of both the phishing application and the spoofed application under one URL. I wanted to expand on the core idea of otu-plz and attempt to make an application that can sit in front of an arbitrary red team phishing application while preventing response teams from accessing the application, and enabling end users to use the phishing application to its full extent.

Bobber performs automatic processing for relative and (some) absolute links to ensure a user can click through either the sites listed under PHISHAPP_DOMAIN or SPOOFED_DOMAIN without performing unnecessary redirects.

**Note:** Bobber is not meant to work with content-heavy streaming platforms (like YouTube or Reddit), but most small sites appear to have base functionality without much issue (XKCD, DaveRamsey, Aetna). Feel free to contact me with necessary updates to load site content better.

## How does bobber know what's meant for the phishing application?
`bobber.py` has simple logic to determine what traffic is meant for the phishing application - it checks to see whether the TOKEN_DELIMITER is active in the GET arguments. Even if the phishing application doesn't support the TOKEN_DELIMITER value in its functionality, this parameter will still be required for initial access. Afterwards, bobber will superimpose the TOKEN_DELIMITER value on every link meant for the phishing application to ensure users can interact with the phishing app seamlessly.

## How does this help secure my phishing campaign?
`bobber.py` ensures that the only way to access the underlying phishing application is with the TOKEN_DELIMITER value in the GET arguments. Once this token is detected, the user will be allowed to interact with the application freely until the token is expired by the time set in TIMEOUT_LENGTH.

When either the token is expired, or the TOKEN_DELIMITER is not passed, `bobber.py` will return content from the SPOOFED_DOMAIN parameter without changing the URL. This means that the only way the phishing application can be accessed via bobber is with an unexpired token, which should promote operational security.
