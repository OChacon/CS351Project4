Starbuck Beagley & Oscar Chacon (Bitbros)
CSCI-351
Project 4: 351dnsclient README

To Run:
	Run the runme.sh with appropriate args
	[ex: "bash runme.sh @<server:port> <domain-name> <record>"]
	server (Required) The IP address of the DNS server, in a.b.c.d format.
	port (Optional) The UDP port number of the DNS server. Default value: 53.
	domain-name (Required) The name to query for
	record (Required) The DNS record to query for, which can be either:
		- A: A records
		- DNSKEY: DNSKEY records
		- DS: DS records

Writeup:
	We decided to write this in python because we wrote our project 2 in python
	and we were already familiar with making a dns client in python. The only
	changes that would be nessesary are converting the dns client into a dnssec 
	client. The biggest challenge by far for us was trying to go up the chain of trust
	to verify the keys and make sure that the records weren't compromised. 
	We were able to get everything else implimented fairly quickly but immedietly
	got hung up on this part of the project. Even without the verification, we were
	at least able to properly display all the other information that we queried
	according to the server given. Most of the error checking was handled,
	however some of the errors in regards to the key verification were probably
	not handled gracefully. If not for the key verification step that we had to
	perform manually, the project would most likely have been a complete 
	success.