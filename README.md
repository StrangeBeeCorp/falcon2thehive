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

```bash
git clone https://github.com/StrangeBeeCorp/falcon2thehive.git
cd falcon2thehive
```

2. **Create and Activate a Virtual Environment (Recommended)**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

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
`python falcon2thehive.py &`

## 🐳 Docker Deployment
Running `falcon2thehive` in Docker is a convenient way to keep your environment consistent and simplify deployment.

### 0. Install Docker

If you don’t already have Docker installed, download it here:
https://docs.docker.com/get-docker/

### 1. Build the Docker Image
```bash
docker build -t falcon2thehive .
```

### 2. Set up your .env accordingly
Make sure to have a well configured `.env`file in your directory.
```
CRWD_BASE_URL=https://api.crowdstrike.com
CRWD_CLIENT_ID=your_client_id
CRWD_CLIENT_SECRET=your_client_secret
THEHIVE_URL=http://my-thehive-url.com
THEHIVE_API_KEY=your_thehive_api_key
# Optionally
THEHIVE_ORG=MYORGNAME
APP_ID=falcon2thehive
```
### 3. Run the Container
Run:
```bash
docker run -d \
  --restart unless-stopped \
  --env-file .env \
  --name f2h falcon2thehive
```

**To view logs for the running connector:**

```bash
docker logs -f f2h
```

### Alternative: Passing environment variables via `-e` flags 
You can also set environment variables directly in the `docker run` command (for quick testing):

```bash
docker run -d \
  --restart unless-stopped \
  -e CRWD_BASE_URL="https://api.crowdstrike.com" \
  -e CRWD_CLIENT_ID="your_client_id" \
  -e CRWD_CLIENT_SECRET="your_client_secret" \
  -e THEHIVE_URL="http://my-thehive-url.com" \
  -e THEHIVE_API_KEY="your_thehive_api_key" \
  --name f2h falcon2thehive
```

### Stopping, Restarting, and Updating Environment Variables

To stop the connector:
```bash
docker stop f2h
```
To start it again (with the same env vars):
```bash
docker start f2h
```
To change environment variables:
1. Stop and remove the existing container:
```bash
docker stop f2h
docker rm f2h
```
2. Start a new one with updated -e flags or an updated .env file:

```bash
docker run -d --restart unless-stopped --env-file .env --name f2h falcon2thehive
```

## Screenshots:
### Alert creation
![alert example](<./assets/alert-example.png>)

### Alert Details
![alert details](<./assets/alert-example-details.png>)

![observables](<./assets/alert-observables-details.png>)