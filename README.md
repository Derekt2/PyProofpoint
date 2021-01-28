# PyProofpoint
Python Wrapper for Proofpoint's Threat Insight API

## Install
```pip3 install pyproofpoint```

## Usage
```
from pyproofpoint import proofpoint
from datetime import date

servicePrincipal = "Service Account"
APISecret = "Service AccountSecret"

pp = proofpoint.ProofPoint(servicePrincipal, APISecret)

my_date = date(2020, 12, 12).isoformat()
interval = "PT12H/" + my_date

campaigns = pp.get_campaign_ids(interval=interval)
print(campaigns)
```