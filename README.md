# VTI-quota_limiter

Users in a Virus Total Enterprise group have the intelligence searches as the default search on the homepage. That's a problem because we have a limited number of intelligence searches per month.

Virus Total won't allow us to define quotas for intelligence searches, so we decided to created a script to manage intelligence searches quotas automatically for our users.

This script will warn users when they used a certain percentage of their quota, remove them from our group if they exceed their weekly quota and reintegrate them in our group on a new week.

⚠️ A new week does not mean on Monday. Virus Total resets the quota on the first of each month. A new week is on the 8th, 15th, 22nd and 29th.

## Installation

Clone this repository or download the zip.

Create a new file called `config.py` using the `config.py.template` file as a reference.

If you want mails to be sent, make sure to fill all mail related variables. Mails can be disabled with the `SEND_MAIL` variable.

If your machine use a proxy, make sure to uncomment the proxy related environmment variables in the `Dockerfile`.

Create/Edit in the `conf` folder the file called `vt_intelligence_user_quota.json` using the `vt_intelligence_user_quota.json.template` file as a reference. General quota and user specific quota can be set in that file. The quota defined there will be the quota for one week. They add up for each week.

If a user has a quota of 50, each week his running quota will increase by 50, meaning that on the first week the user will have 50 queries, then 100 on the second week and 150 on the third week.

Run the following command

```(shell)
docker-compose build
```

If you update the `config.py` file, you will need to rerun this command or force the build on launch of the docker-compose.

## Usage

To launch the script run the following command

```(shell)
docker-compose up -d
```

The script will run once, download the list of user of your group, check if users should be warned or removed, remove the users that need to be removed.

On each new week, the script will check if removed users should be reinstated in the group. If a use was reinstated manually, the script will notice and will remove that user again if his user specific quota was not adjusted accordingly.

This script can be launched as many times as you wish per day. You are free to decide how you wish to launch the script.
