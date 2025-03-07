# falcon2thehive

A simple Python connector that allows to send your CrowdStrike Falcon detections to The Hive platform.
This connector is a *work in progress* and is being developed to be compatible with TheHive 5.

Alerts are generated in TheHive and support the extraction of observables and TTPs, as well as defining a format for the title, description, and tags.


## Pre-requisites:
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

## Configuration:
The script uses environment variables for configuration. Update or set the following environment variables as needed:

- **CRWD_BASE_URL**: URL for the CrowdStrike API (defaults to `https://api.crowdstrike.com`). Supports short values like `US-1`, `US-2`, `EU-1`, `US-GOV-1`.
- **CRWD_CLIENT_ID**: Your Falcon API's Client ID.
- **CRWD_CLIENT_SECRET**: Your Falcon API's Secret.
- **THEHIVE_URL**: URL of your TheHive instance (defaults to `http://127.0.0.1:9000`).
- **THEHIVE_API_KEY**: Your TheHive API Key.
- **THEHIVE_ORG**: *(Optional)* Specify an organization if your user belongs to multiple organizations.
- **APP_ID**: *(Optional)* Application ID (defaults to `falcon2thehive`).

You can set these variables in your shell.

```
export CRWD_BASE_URL="https://api.crowdstrike.com"
export CRWD_CLIENT_ID="your_client_id"
export CRWD_CLIENT_SECRET="your_client_secret"
export THEHIVE_URL="http://my-thehive-url.com"
export THEHIVE_API_KEY="your_thehive_api_key"
# Optionally
export THEHIVE_ORG="MYORGNAME"  
```

## Usage:
To run the script on background :
`falcon2thehive.py &`

## Screenshots:
### Alert creation
![alert example](<./assets/alert-example.png>)

### Alert Details
![alert details](<./assets/alert-example-details.png>)

![observables](<./assets/alert-observables-details.png>)