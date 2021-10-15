import requests

class ProofpointAPIError(BaseException):
    pass

class ProofPoint(object):
    '''ProofPoint Threat Insights API Class.
    
    '''
    
    def __init__(self, servicePrincipal, APISecret):
        self.auth = (servicePrincipal, APISecret)
        self.base_url = "https://tap-api-v2.proofpoint.com"
    
    def get_campaign_ids(self, interval, size=100, page=1):
        '''Fetch a list of IDs of campaigns active in a time window sorted by the last updated timestamp.
        
        :param interval:A string containing an ISO8601-formatted interval. The minimum interval is 30 seconds. The maximum interval is 1 day. E.G: 2020-05-01T12:00:00Z/2020-05-01T13:00:00Z, or PT30M/2020-05-01T12:30:00Z
        :param size:The maximum number of campaign IDs to produce in the response. Defaults to 100 and the max supported value is 200.
        :param page: The page of results to return, in multiples of the specified size (or 100, if no size is explicitly chosen). Defaults to 1.
        '''
        uri = "/v2/campaign/ids"
        params = {"interval": interval,
        'page': page,
        'size': size}
        return self.send_request(uri, params=params)
    
    def get_vap(self, window, size=1000, page=1):   
        '''Fetch the identities and attack index breakdown of Very Attacked People within your organization for a given period.
        
        :param window:An integer indicating how many days the data should be retrieved for. Accepted values are 14, 30 and 90.
        :param size:The maximum number of VAPs to produce in the response. The attackIndex value determine the order of results. Defaults to 1000.
        :param page: The page of results to return, in multiples of the specified size (or 1000, if no size is explicitly chosen). Defaults to 1.
        '''
        uri = "/v2/people/vap"
        params = {"window": window,
        'page': page,
        'size': size}
        return self.send_request(uri, params=params)

    def get_top_clickers(self, window, size=100, page=1):
        '''Fetch the identities and attack index of the top clickers within your organization for a given period. Top clickers are the users who have demonstrated a tendency to click on malicious URLs, regardless of whether the clicks were blocked or not. 
        
        :param window:An integer indicating how many days the data should be retrieved for. Accepted values are 14, 30 and 90.
        :param size:The maximum number of top clickers to produce in the response. The attackIndex value determine the order of results. Defaults to 100 and the max supported value is 200.
        :param page: The page of results to return, in multiples of the specified size (or 100, if no size is explicitly chosen). Defaults to 1.
        '''
        uri = "/v2/people/top-clickers"
        params = {"window": window,
        'page': page,
        'size': size}
        return self.send_request(uri, params=params)
    
    def get_campaign(self, cid):
        '''Fetch detailed information for a given campaign.
        
        :param cid:A string representing a campaignID
        ''' 
        uri = f"/v2/campaign/{cid}"
        return self.send_request(uri)

    def get_forensic(self, threatId=None, campaignId=None, includeCampaignForensics=False):
        '''Fetch forensic information for a given threat or campaign.
        
        :param threatId:A string containing a threat identifier.
        :param campaignId:A string containing a campaignId.
        :param includeCampaignForensics:A boolean value, defaulting to false. May optionally be used with the threatId parameter. It cannot be used with the campaignId parameter.
        
        ''' 
        uri = f"/v2/forensics"
        if not (threatId or campaignId):
            raise ValueError("Must provide threatID or CampaignID")
        params = {
            'threatId': threatId, 
            'campaignId': campaignId, 
            'includeCampaignForensics': includeCampaignForensics
        }
        return self.send_request(uri, params=params)
    
    def get_clicks_blocked(self, interval=None, sinceSeconds=None, sinceTime=None, dataformat='syslog', threatType=None, threatStatus=None):
        '''Fetch events for clicks to malicious URLs blocked in the specified time period
        
        :param interval:A string containing an ISO8601-formatted interval. If this interval overlaps with previous requests for data, records from the previous request may be duplicated. The minimum interval is thirty seconds. The maximum interval is one hour.
        :param sinceSeconds:An integer representing a time window in seconds from the current API server time. The start of the window is the current API server time, rounded to the nearest minute, less the number of seconds provided. The end of the window is the current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result.
        :param sinceTime:A string containing an ISO8601 date. It represents the start of the data retrieval period. The end of the period is determined by current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result.
        :param dataformat:A string specifying the format in which data is returned. If no format is specified, syslog will be used as the default. The following values are accepted: JSON, syslog
        :param threatType:A string specifying which threat type will be returned in the data. If no value is specified, all threat types are returned. The following values are accepted: url, attachment, messageText
        :param threatStatus:A string specifying which threat statuses will be returned in the data. If no value is specified, active and cleared threats are returned. The following values are accepted: active, cleared, falsePositive
        
        ''' 
        uri = f"/v2/siem/clicks/blocked"
        if not (interval or sinceSeconds or sinceTime):
            raise ValueError("Must provide sinceTime or sinceSeconds or interval")
        params = {
            'interval': interval, 
            'sinceSeconds': sinceSeconds, 
            'sinceTime': sinceTime,
            'format': dataformat,
            'threatType': threatType,
            'threatStatus': threatStatus
        }
        return self.send_request(uri, params=params)
    
    def get_clicks_permitted(self, interval=None, sinceSeconds=None, sinceTime=None, dataformat='syslog', threatType=None, threatStatus=None):
        '''Fetch events for clicks to malicious URLs permitted in the specified time period
        
        :param interval:A string containing an ISO8601-formatted interval. If this interval overlaps with previous requests for data, records from the previous request may be duplicated. The minimum interval is thirty seconds. The maximum interval is one hour.
        :param sinceSeconds:An integer representing a time window in seconds from the current API server time. The start of the window is the current API server time, rounded to the nearest minute, less the number of seconds provided. The end of the window is the current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result.
        :param sinceTime:A string containing an ISO8601 date. It represents the start of the data retrieval period. The end of the period is determined by current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result.
        :param dataformat:A string specifying the format in which data is returned. If no format is specified, syslog will be used as the default. The following values are accepted: JSON, syslog
        :param threatType:A string specifying which threat type will be returned in the data. If no value is specified, all threat types are returned. The following values are accepted: url, attachment, messageText
        :param threatStatus:A string specifying which threat statuses will be returned in the data. If no value is specified, active and cleared threats are returned. The following values are accepted: active, cleared, falsePositive
        
        '''         
        uri = f"/v2/siem/clicks/permitted"
        if not (interval or sinceSeconds or sinceTime):
            raise ValueError("Must provide sinceTime or sinceSeconds or interval")
        params = {
            'interval': interval, 
            'sinceSeconds': sinceSeconds, 
            'sinceTime': sinceTime,
            'format': dataformat,
            'threatType': threatType,
            'threatStatus': threatStatus
        }
        return self.send_request(uri, params=params)
    
    def get_messages_blocked(self, interval=None, sinceSeconds=None, sinceTime=None, dataformat='syslog', threatType=None, threatStatus=None):
        '''Fetch events for messages blocked in the specified time period which contained a known threat
        
        :param interval:A string containing an ISO8601-formatted interval. If this interval overlaps with previous requests for data, records from the previous request may be duplicated. The minimum interval is thirty seconds. The maximum interval is one hour.
        :param sinceSeconds:An integer representing a time window in seconds from the current API server time. The start of the window is the current API server time, rounded to the nearest minute, less the number of seconds provided. The end of the window is the current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result.
        :param sinceTime:A string containing an ISO8601 date. It represents the start of the data retrieval period. The end of the period is determined by current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result.
        :param dataformat:A string specifying the format in which data is returned. If no format is specified, syslog will be used as the default. The following values are accepted: JSON, syslog
        :param threatType:A string specifying which threat type will be returned in the data. If no value is specified, all threat types are returned. The following values are accepted: url, attachment, messageText
        :param threatStatus:A string specifying which threat statuses will be returned in the data. If no value is specified, active and cleared threats are returned. The following values are accepted: active, cleared, falsePositive
        
        '''
        uri = f"/v2/siem/messages/blocked"
        if not (interval or sinceSeconds or sinceTime):
            raise ValueError("Must provide sinceTime or sinceSeconds or interval")
        params = {
            'interval': interval, 
            'sinceSeconds': sinceSeconds, 
            'sinceTime': sinceTime,
            'format': dataformat,
            'threatType': threatType,
            'threatStatus': threatStatus
        }
        return self.send_request(uri, params=params)
    
    def get_messages_delivered(self, interval=None, sinceSeconds=None, sinceTime=None, dataformat='syslog', threatType=None, threatStatus=None):
        '''Fetch events for messages delivered in the specified time period which contained a known threat
        
        :param interval:A string containing an ISO8601-formatted interval. If this interval overlaps with previous requests for data, records from the previous request may be duplicated. The minimum interval is thirty seconds. The maximum interval is one hour.
        :param sinceSeconds:An integer representing a time window in seconds from the current API server time. The start of the window is the current API server time, rounded to the nearest minute, less the number of seconds provided. The end of the window is the current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result.
        :param sinceTime:A string containing an ISO8601 date. It represents the start of the data retrieval period. The end of the period is determined by current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result.
        :param dataformat:A string specifying the format in which data is returned. If no format is specified, syslog will be used as the default. The following values are accepted: JSON, syslog
        :param threatType:A string specifying which threat type will be returned in the data. If no value is specified, all threat types are returned. The following values are accepted: url, attachment, messageText
        :param threatStatus:A string specifying which threat statuses will be returned in the data. If no value is specified, active and cleared threats are returned. The following values are accepted: active, cleared, falsePositive
        
        '''
        uri = f"/v2/siem/messages/delivered"
        if not (interval or sinceSeconds or sinceTime):
            raise ValueError("Must provide sinceTime or sinceSeconds or interval")
        params = {
            'interval': interval, 
            'sinceSeconds': sinceSeconds, 
            'sinceTime': sinceTime,
            'format': dataformat,
            'threatType': threatType,
            'threatStatus': threatStatus
        }
        return self.send_request(uri, params=params)

    def get_threat_info(self, threatId):
        '''The Threat API allows administrators to pull detailed attributes about individual threats observed in their environment.
            It can be used to retrieve more intelligence for threats identified in the SIEM or Campaign API responses.
        
        :param threatId:A string containing a threat identifier.

        
        '''
        uri = f"/v2/threat/summary/{threatId}"
        if not (threatId):
            raise ValueError(f"Must provide valid ThreatId, value provided: {threatId}")
        return self.send_request(uri)
    
    def get_issues(self, interval=None, sinceSeconds=None, sinceTime=None, dataformat='syslog', threatType=None, threatStatus=None):
        '''Fetch events for clicks to malicious URLs permitted and messages delivered containing a known attachment threat within the specified time period
        
        :param interval:A string containing an ISO8601-formatted interval. If this interval overlaps with previous requests for data, records from the previous request may be duplicated. The minimum interval is thirty seconds. The maximum interval is one hour.
        :param sinceSeconds:An integer representing a time window in seconds from the current API server time. The start of the window is the current API server time, rounded to the nearest minute, less the number of seconds provided. The end of the window is the current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result.
        :param sinceTime:A string containing an ISO8601 date. It represents the start of the data retrieval period. The end of the period is determined by current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result.
        :param dataformat:A string specifying the format in which data is returned. If no format is specified, syslog will be used as the default. The following values are accepted: JSON, syslog
        :param threatType:A string specifying which threat type will be returned in the data. If no value is specified, all threat types are returned. The following values are accepted: url, attachment, messageText
        :param threatStatus:A string specifying which threat statuses will be returned in the data. If no value is specified, active and cleared threats are returned. The following values are accepted: active, cleared, falsePositive
        
        '''
        uri = f"/v2/siem/issues"
        if not (interval or sinceSeconds or sinceTime):
            raise ValueError("Must provide sinceTime or sinceSeconds or interval")
        params = {
            'interval': interval, 
            'sinceSeconds': sinceSeconds, 
            'sinceTime': sinceTime,
            'format': dataformat,
            'threatType': threatType,
            'threatStatus': threatStatus
        }
        return self.send_request(uri, params=params)
    
    def get_all_events(self, interval=None, sinceSeconds=None, sinceTime=None, dataformat='syslog', threatType=None, threatStatus=None):
        '''Fetch events for all clicks and messages relating to known threats within the specified time period
        
        :param interval:A string containing an ISO8601-formatted interval. If this interval overlaps with previous requests for data, records from the previous request may be duplicated. The minimum interval is thirty seconds. The maximum interval is one hour.
        :param sinceSeconds:An integer representing a time window in seconds from the current API server time. The start of the window is the current API server time, rounded to the nearest minute, less the number of seconds provided. The end of the window is the current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result.
        :param sinceTime:A string containing an ISO8601 date. It represents the start of the data retrieval period. The end of the period is determined by current API server time rounded to the nearest minute. If JSON output is selected, the end time is included in the returned result.
        :param dataformat:A string specifying the format in which data is returned. If no format is specified, syslog will be used as the default. The following values are accepted: JSON, syslog
        :param threatType:A string specifying which threat type will be returned in the data. If no value is specified, all threat types are returned. The following values are accepted: url, attachment, messageText
        :param threatStatus:A string specifying which threat statuses will be returned in the data. If no value is specified, active and cleared threats are returned. The following values are accepted: active, cleared, falsePositive
        
        '''
        uri = f"/v2/siem/all"
        if not (interval or sinceSeconds or sinceTime):
            raise ValueError("Must provide sinceTime or sinceSeconds or interval")
        params = {
            'interval': interval, 
            'sinceSeconds': sinceSeconds, 
            'sinceTime': sinceTime,
            'format': dataformat,
            'threatType': threatType,
            'threatStatus': threatStatus
        }
        return self.send_request(uri, params=params)

    def send_request(self, uri, params=None):
        url = self.base_url + uri
        try:
            r = requests.get(url, auth=self.auth, params=params)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            raise ProofpointAPIError(f"Error connecting to Proofpoint API: {e}: {r.content}")