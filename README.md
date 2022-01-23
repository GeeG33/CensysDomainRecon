# Censys Domain Recon

## Install
This script requires Python3 to run.

To install:
- Clone the repo or copy files to disk.
- Create virtual environment.
- Install and configure Censys.
- Install requirements.

### Virtual Env
It is highly recommended that you run this in a virtual environment.

Install:
```
pip install virtualenv
```
Create venv:
```
virtualenv venv
```
#### MacOS / LInux
```
source venv/bin/activate
```
#### Windows
```
venv\Scripts\activate
```

### Censys Configuration
You need to install and configure the Censys package to make API calls. 

Full Censys Documentation can be found [here](https://censys-python.readthedocs.io/en/stable/quick-start.html).

```
pip install censys
```
Then run:
```
censys configure
```
And enter you API ID and Secret.

Or you can set environment variables:
```
export CENSYS_API_ID=<your-api-id>
export CENSYS_API_SECRET=<your-api-secret>
```

Finally install the requirements for this package:

```
pip install -r requirements.txt
```

## Using Censys Domain Recon

The script takes one domain at a time, presents interesting information such as wether the domain is using a shared hosting provider, possible technologies used and possible subdomains to the terminal and will generate a detailed json report for further analysis. (see examples folder for sample output)

### Commands

```
usage: arguments [-h] -d DOMAIN [-o OUTFILE]

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        domain you wish to search for
  -o OUTFILE, --outfile OUTFILE
                        filename to put results in. default is outfile.json
```

#### Example

```
python3 censys_domain_report.py -d gee-gee.uk -o gee-gee-uk.json
```

