# falcon2thehive

A simple Python connector that allows to send your CrowdStrike Falcon detections to The Hive platform.
This connector is a *work in progress* and is being developed to be compatible with TheHive 5.

Alerts are generated in TheHive and support the extraction of observables and TTPs, as well as defining a format for the title, description, and tags.


## Pre-requisites :
-   Python3 
- [TheHive4py v2](https://github.com/TheHive-Project/TheHive4py)
- [FalconPy SDK ](https://github.com/CrowdStrike/falconpy)

## Installation
1. **Clone the Repository**

```git clone https://github.com/StrangeBeeCorp/falcon2thehive.git```

2. **Navigate to the Project Directory**

```cd falcon2thehive```

3. Install Dependencies

```pip install -r requirements.txt```

## Configuration :
Edit the `falcon2thehive` script and adapt the following lines with your own values :
```
g_client_id = 'XXXXXXXXXXXXXX'    # Your Falcon API's Client ID
g_client_secret = 'YYYYYYYYYY'    # Your Falcon API's Secret        
THEHIVE_URL = 'http://127.0.0.1:9000'   # URL of your TheHive instance
THEHIVE_API_KEY = 'XXXXXXXXXXXXXXX'     # Your Hive API Key
THEHIVE_ORG = None # Optional - define a specific ORG if your user is in multiple organization
```

## Usage :
To run the script on background :
`falcon2thehive.py &`

## Screenshots:
### Alert creation
![alert example](<./assets/alert-example.png>)

### Alert Details
![alert details](<./assets/alert-example-details.png>)

![observables](<./assets/alert-observables-details.png>)