[comment]: # "Auto-generated SOAR connector documentation"
# HoneyDB

Publisher: Splunk  
Connector Version: 2\.0\.7  
Product Vendor: HoneyDB  
Product Name: HoneyDB  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

Performs investigative actions on the HoneyDB service

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a HoneyDB asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_id** |  required  | string | HoneyDB API ID
**api\_key** |  required  | password | Threat information API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[lookup ip](#action-lookup-ip) - Check for the presence of an IP in a threat intelligence feed  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup ip'
Check for the presence of an IP in a threat intelligence feed

Type: **investigate**  
Read only: **True**

Source feed to use for IP lookup\:<ul><li><b>Both</b>\: Merges the Bad Hosts and Twitter feed list of JSON dictionaries and searches for the IP with the additional information from Twitter for that specific IP</li><li><b>Bad Hosts</b>\: Searches only in the list of bad hosts with no additional data from Twitter</li><li><b>Twitter</b>\: Searches the IP in the Twitter feed with a list of tweets associated with that IP</li></ul>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to lookup | string |  `ip` 
**feed** |  optional  | Source feed\: 'Both', 'Bad Hosts', 'Twitter' | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.feed | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.count | numeric | 
action\_result\.data\.\*\.feed | string | 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.last\_seen | string | 
action\_result\.data\.\*\.tweet\.created | string | 
action\_result\.data\.\*\.tweet\.id | string | 
action\_result\.data\.\*\.tweet\.screen\_name | string | 
action\_result\.data\.\*\.tweet\.text | string | 
action\_result\.summary\.bad\_hosts\_count | numeric | 
action\_result\.summary\.bad\_hosts\_last\_seen | string | 
action\_result\.summary\.ip | string | 
action\_result\.summary\.twitter\_count | numeric | 
action\_result\.summary\.twitter\_last\_seen | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 