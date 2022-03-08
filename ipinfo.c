#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <json-c/json.h>
#include <string.h>

#define HEADERLEN 100
#define BUFFER 1024

void printUsage(char *arg);
void json(char *buffer);
int DNSLookup(char* hostname , char* ip);
void fixjson(char *buffer, int option);

int main(int argc, char *argv[])
{
	//Adding an all options soon so thats why im using a struct.
	struct headers
	{
		char ipinfo[HEADERLEN];
		char privacy[HEADERLEN];
		char asnAPI[HEADERLEN];
		char company[HEADERLEN];
		char abuse[HEADERLEN];
	};

	struct headers data;
	
	int opt, option = 0;

	if (argc < 2)
	{
		option = 1;
        strncpy(data.ipinfo, "GET / HTTP/1.1\r\nHost: www.ipinfo.io\r\n\r\n", 100);
	}

	int s;
	char buffer[BUFFER];
	char *ip;
	char *jsonbody;

	while ((opt = getopt(argc, argv, "hp:m:c:a:s:")) != -1)
	{
		switch (opt)
		{
			case 'p':
				option = 2;
                ip = strndup(optarg, 20);
                DNSLookup(ip, ip);
               	snprintf(data.privacy, sizeof(struct headers), "POST /products/proxy-vpn-detection-api?value=%s&dataset=proxy-vpn-detection HTTP/1.1\r\nContent-Length: 0\r\nHost: www.ipinfo.io\r\n\r\n", ip);
				break;

			case 's':
				option = 1;
                ip = strndup(optarg, 20);
                DNSLookup(ip, ip);
                snprintf(data.ipinfo, sizeof(struct headers), "GET /%s/ HTTP/1.1\r\nHost: www.ipinfo.io\r\n\r\n", ip);
				break;

			case 'm':
				option = 3;
                ip = strndup(optarg, 20);
                DNSLookup(ip, ip);
                snprintf(data.asnAPI, sizeof(struct headers), "POST /products/asn-api?value=%s HTTP/1.1\r\nContent-Length: 0\r\nHost: www.ipinfo.io\r\n\r\n", ip);
				break;

			case 'c':
				option = 4;
                ip = strndup(optarg, 20);
                DNSLookup(ip, ip);
                snprintf(data.company, sizeof(struct headers), "POST /products/ip-company-api?value=%s&dataset=company HTTP/1.1\r\nContent-Length: 0\r\nHost: www.ipinfo.io\r\n\r\n", ip);
				break;
			case 'a':
				option = 5;
                ip = strndup(optarg, 20);
                DNSLookup(ip, ip);
                snprintf(data.abuse, sizeof(struct headers), "POST /products/ip-abuse-contact-api?value=%s&dataset=abuse-contact HTTP/1.1\r\nContent-Length: 0\r\nHost: www.ipinfo.io\r\n\r\n", ip);
				break;
			case 'h':
				printUsage(argv[0]);
				return 0;

			default:
				printUsage(argv[0]);
				return 1;
		}
	}

	s = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in sa;

	memset(&sa, 0, sizeof(sa));

	sa.sin_family = AF_INET;
	sa.sin_port = htons(80);
	sa.sin_addr.s_addr = inet_addr("34.117.59.81");

	if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) == -1)
	{
		perror("Error");
		return 1;
	}
	/*I know i could have skipped this if i didnt use a sturct.*/
	if (option == 1)
	{
		send(s, data.ipinfo, sizeof(struct headers), 0);

	} else if (option == 2)
	{
		send(s, data.privacy, sizeof(struct headers), 0);
		
	} else if (option == 3)
	{
		send(s, data.asnAPI, sizeof(struct headers), 0);
		
	} else if (option == 4)
	{
		send(s, data.company, sizeof(struct headers), 0);
	
	} else if (option == 5)
	{
		send(s, data.abuse, sizeof(struct headers), 0);
	} 

	recv(s, &buffer, sizeof(buffer), 0);
	close(s);

	/*Removes the stupid headers from the response*/
    jsonbody = strstr(buffer, "\r\n\r\n");
    jsonbody += 4;

	fixjson(jsonbody, option);

	return 0;	
}

int DNSLookup(char *hostname , char *ip)
{
    struct hostent *hent;
    struct in_addr **addr_list;
    int i;
    if ((hent = gethostbyname(hostname)) == NULL)
    {
        herror("\033[38;2;255;0;0mError getting DNS records\n");

        return 1;
    }
    addr_list = (struct in_addr **) hent->h_addr_list;
    for(i = 0; addr_list[i] != NULL; i++)
    {
        strcpy(ip , inet_ntoa(*addr_list[i]));
        return 0;
    }
    return 1;
}


/*WARNING! You will become blind if u see this function! Because its so shit*/
void fixjson(char *buffer, int option)
{
	/* Parsing every json object, looks awful :(*/
    struct json_object *parsed_json;
    
    struct json_object *ip;
    struct json_object *hostname;
    struct json_object *city;
    struct json_object *region;
    struct json_object *country;
    struct json_object *loc;
    struct json_object *org;
    struct json_object *postal;
    struct json_object *timezone;

    struct json_object *privData;
    struct json_object *vpn;
	struct json_object *proxy;
	struct json_object *tor;
	struct json_object *relay;
	struct json_object *hosting;
	struct json_object *service;

	struct json_object *asnData;
	struct json_object *asn;
	struct json_object *name;
	struct json_object *domain;
	struct json_object *route;
	struct json_object *type;

	struct json_object *compdata;
	struct json_object *comname;
	struct json_object *compdomain;
	struct json_object *comptype;
	struct json_object *network;

	struct json_object *abdata;
	struct json_object *address;
	struct json_object *abcountry;
	struct json_object *email;
	struct json_object *abname;
	struct json_object *abnetwork;
	struct json_object *phone;

    parsed_json = json_tokener_parse(buffer);
    
    json_object_object_get_ex(parsed_json, "ip", &ip);
    json_object_object_get_ex(parsed_json, "hostname", &hostname);
    json_object_object_get_ex(parsed_json, "city", &city);
    json_object_object_get_ex(parsed_json, "region", &region);
    json_object_object_get_ex(parsed_json, "country", &country);
    json_object_object_get_ex(parsed_json, "loc", &loc);
    json_object_object_get_ex(parsed_json, "org", &org);
    json_object_object_get_ex(parsed_json, "postal", &postal);
    json_object_object_get_ex(parsed_json, "timezone", &timezone);

    json_object_object_get_ex(parsed_json, "data", &privData);
    json_object_object_get_ex(privData, "vpn", &vpn);
    json_object_object_get_ex(privData, "proxy", &proxy);
    json_object_object_get_ex(privData, "tor", &tor);
    json_object_object_get_ex(privData, "relay", &relay);
    json_object_object_get_ex(privData, "hosting", &hosting);
    json_object_object_get_ex(privData, "service", &service);

    json_object_object_get_ex(parsed_json, "data", &asnData);
    json_object_object_get_ex(asnData, "asn", &asn);
    json_object_object_get_ex(asnData, "name", &name);
    json_object_object_get_ex(asnData, "domain", &domain);
    json_object_object_get_ex(asnData, "route", &route);
    json_object_object_get_ex(asnData, "type", &type);

    json_object_object_get_ex(parsed_json, "data", &compdata);
    json_object_object_get_ex(compdata, "domain", &compdomain);
    json_object_object_get_ex(compdata, "name", &comname);
    json_object_object_get_ex(compdata, "network", &network);
    json_object_object_get_ex(compdata, "type", &comptype);

    json_object_object_get_ex(parsed_json, "data", &abdata);
    json_object_object_get_ex(abdata, "address", &address);
    json_object_object_get_ex(abdata, "country", &abcountry);
    json_object_object_get_ex(abdata, "email", &email);
    json_object_object_get_ex(abdata, "name", &abname);
    json_object_object_get_ex(abdata, "network", &abnetwork);
    json_object_object_get_ex(abdata, "phone", &phone);

	switch (option)
	{
		case 1:
		    printf("IP: %s\n"
		        "Hostname: %s\n"
		        "City: %s\n"
		        "Region: %s\n"
		        "Country: %s\n"
		        "Location: %s\n"
		        "Org: %s\n"
		        "Postal: %s\n"
		        "Timezone: %s\n", json_object_get_string(ip),
		        json_object_get_string(hostname),
		        json_object_get_string(city),
		        json_object_get_string(region),
		        json_object_get_string(country),
		        json_object_get_string(loc),
		        json_object_get_string(org),
		        json_object_get_string(postal),
		        json_object_get_string(timezone));
			break;
		case 2:
		    printf("VPN: %s\n"
		        "Proxy: %s\n"
		        "Tor: %s\n"
		        "Relay: %s\n"
		        "Hosting: %s\n"
		        "Service: %s\n", json_object_get_string(vpn),
		        json_object_get_string(proxy),
		        json_object_get_string(tor),
		        json_object_get_string(relay),
		        json_object_get_string(hosting),
		        json_object_get_string(service));
		    break;
		case 3:
		    printf("ASN: %s\n"
		        "Name: %s\n"
		        "Domain: %s\n"
		        "Route: %s\n"
		        "Type: %s\n", json_object_get_string(asn),
		        json_object_get_string(name),
		        json_object_get_string(domain),
		        json_object_get_string(route),
		        json_object_get_string(type));
		    break;
		case 4: //company details
		    printf("Domain: %s\n"
		        "Name: %s\n"
		        "Network: %s\n"
		        "Type: %s\n", json_object_get_string(compdomain),
		        json_object_get_string(comname),
		        json_object_get_string(network),
		        json_object_get_string(comptype));
		    break;
		case 5:
		    printf("Address: %s\n"
		        "Country: %s\n"
		        "Email: %s\n"
		        "Name: %s\n"
		        "Network: %s\n"
		        "Phone: %s\n", json_object_get_string(address),
		        json_object_get_string(abcountry),
		        json_object_get_string(email),
		        json_object_get_string(abname),
		        json_object_get_string(abnetwork),
		        json_object_get_string(phone));
		    break;
		default:
			printf("Unknown Error.\n");
			exit(1);
	}

}

void printUsage(char *arg)
{
	printf("Usage: %s [-s ip] [-p ip] [-m ip] [-c ip] [-a ip]\n"
		"\t[-p ip] Detects VPN/TOR/Service/Hosting/Relay\n"
		"\t[-m ip] ASN Details\n"
		"\t[-c ip] Company details (If any)\n"
		"\t[-a ip] Abuse contact information\n"
		"\t[-s ip] Search basic information about the IP, geoloc etc\n", arg);
}