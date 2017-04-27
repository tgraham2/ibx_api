import re
import requests
import json
#import cssh_lib

class InfobloxNotFoundException(Exception):
    pass

class InfobloxNoIPavailableException(Exception):
    pass

class InfobloxNoNetworkAvailableException(Exception):
    pass

class InfobloxGeneralException(Exception):
    pass

class InfobloxBadInputParameter(Exception):
    pass
class Infoblox(object):
    """ Implements the following subset of Infoblox IPAM API via REST API
    	create_host_record
	delete_host_record
	get_next_available_ip
    """

    def __init__(self, iba_ipaddr="10.41.100.50", 
                 iba_user="tgraham", iba_password="", \
                 iba_wapi_version = "1.6" , \
                 iba_dns_view="InternalDNS", iba_network_view = "default", \
                 iba_verify_ssl=False):
        """ Class initialization method
        :param iba_ipaddr: IBA IP address of management interface
        :param iba_user: IBA user name
        :param iba_password: IBA user password
        :param iba_wapi_version: IBA WAPI version (example: 1.0)
        :param iba_dns_view: IBA default view
        :param iba_network_view: IBA default network view
        :param iba_verify_ssl: IBA SSL certificate validation (example: False)
        """
        self.iba_host = iba_ipaddr
        self.iba_user = iba_user
        self.iba_password = iba_password
        self.iba_wapi_version = iba_wapi_version
        self.iba_dns_view = iba_dns_view
        self.iba_network_view = iba_network_view
        self.iba_verify_ssl = iba_verify_ssl
        self.base_url = 'https://' + self.iba_host + '/wapi/v' + self.iba_wapi_version + '/'
        #    base_url = 'https://' + self.iba_host + '/wapi/v' + self.iba_wapi_version + '/'

    def get_host_by_regexp(self, fqdn):
        """ Implements IBA REST API call to retrieve host records by fqdn regexp filter
        Returns array of host names in FQDN matched to given regexp filter
        :param fqdn: hostname in FQDN or FQDN regexp filter
        """
        network = '10.246.124.0/22'
        rest_url = 'https://' + self.iba_host + '/wapi/v' + self.iba_wapi_version + '/record:host?name~=' + fqdn  #+ '&view=' + self.iba_dns_view 
                       # '&network=' + network 
        hosts = []
        try:
            r = requests.get(url=rest_url, auth=(self.iba_user, self.iba_password), verify=self.iba_verify_ssl)
            r_json = r.json()
            if r.status_code == 200:
                if len(r_json) > 0:
                    for host in r_json:
                        hosts.append(host['name'])
                        return hosts
                else:
                    raise InfobloxNotFoundException("No hosts found for regexp filter: " + fqdn)
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise

    def get_next_available_ip(self, network):
        """ Implements IBA next_available_ip REST API call
        Returns IP v4 address
        :param network: network in CIDR format
        """
        rest_url = 'https://' + self.iba_host + '/wapi/v' + self.iba_wapi_version + '/network?network=' + network + '&network_view=' + self.iba_network_view
        print "GET:",rest_url
        try:
            r = requests.get(url=rest_url, auth=(self.iba_user, self.iba_password), verify=self.iba_verify_ssl)
            r_json = r.json()
            print "GET:",r_json
            if r.status_code == 200:
                if len(r_json) > 0:
                    net_ref = r_json[0]['_ref']
                    rest_url = self.base_url + net_ref + '?_function=next_available_ip&num=1'
                    r = requests.post(url=rest_url, auth=(self.iba_user, self.iba_password), verify=self.iba_verify_ssl)
                    r_json = r.json()
                    if r.status_code == 200:
                        ip_v4 = r_json['ips'][0]
                        return ip_v4
                    else:
                        if 'text' in r_json:
                            if 'code' in r_json and r_json['code'] == 'Client.Ibap.Data':
                                raise InfobloxNoIPavailableException(r_json['text'])
                            else:
                                raise InfobloxGeneralException(r_json['text'])
                        else:
                            r.raise_for_status()
                else:
                    raise InfobloxNotFoundException("No requested network found: " + network)
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise


    def create_host_record(self, address, fqdn):
        """ Implements IBA REST API call to create IBA host record
        Returns IP v4 address assigned to the host
        :param address: IP v4 address or NET v4 address in CIDR format to get next_available_ip from
        :param fqdn: hostname in FQDN
        """
        if re.match("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$", address):
            ipv4addr = 'func:nextavailableip:' + address
        else:
            if re.match("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", address):
                ipv4addr = address
            else:
                raise InfobloxBadInputParameter('Expected IP or NET address in CIDR format')
        rest_url = self.base_url + 'record:host' + '?_return_fields=ipv4addrs'
        payload = '{"ipv4addrs": [{"configure_for_dhcp": false,  \
                    "ipv4addr": "' + ipv4addr + '"}], \
                    "configure_for_dns": false, \
                    "name": "' + fqdn + '" }'
        try:
            r = requests.post(url=rest_url, auth=(self.iba_user, self.iba_password), verify=self.iba_verify_ssl, data=payload)
            r_json = r.json()
            if r.status_code == 200 or r.status_code == 201:
                return r_json['ipv4addrs'][0]['ipv4addr']
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise
    def delete_host_record(self, hostAddr):
        """ Implements IBA REST API call to delete IBA host record
        :param fqdn: hostname in FQDN
        """
        h = {"Content-Type" : "application/json"}
        #rest_url = self.base_url + 'record:host?name=' + fqdn + '&view=' + self.iba_dns_view
        rest_url = self.base_url + 'ipv4address?status=USED&ip_address=%s' % hostAddr
        try:
            print 'URL:',rest_url
            r = requests.get(url=rest_url, auth=(self.iba_user, self.iba_password), verify=self.iba_verify_ssl, headers=h)
            r_json = r.json()
            if r.status_code == 200:
                if len(r_json) > 0:
                    host_ref = r_json[0]['_ref']
                    print 'DEL:',host_ref
                    rest_url = 'https://' + self.iba_host + '/wapi/v' + self.iba_wapi_version + '/' + host_ref
                    r = requests.delete(url=rest_url, auth=(self.iba_user, self.iba_password), verify=self.iba_verify_ssl)
                    if r.status_code == 200:
                        return
                    else:
                        if 'text' in r_json:
                            raise InfobloxGeneralException(r_json['text'])
                        else:
                            r.raise_for_status()
                else:
                    raise InfobloxNotFoundException("Retuned value error")
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise
        
def getTunAddr(dsName):
    import netaddr
    import sys
    import time
    from cssh_lib import csshpw
    #
    x=Infoblox(iba_password=csshpw())

    resp1=x.get_next_available_ip("10.246.124.0/22")
    resp2=x.get_next_available_ip("10.246.132.0/22")
    newip1=str(resp1)
    newip2=str(resp2)
    dec1 = int(netaddr.IPAddress(newip1))
    dec2 = int(netaddr.IPAddress(newip2))
    print "DELTA:",dec2-dec1
    if (dec2-dec1) == 2048:
        print "Adding:", newip1, newip2
        resp1=x.create_host_record(newip1,'%s-100' % dsname)
        resp2=x.create_host_record(newip2,'%s-200' % dsname)
        print resp1,resp2
    else:
        raise Exception()
    return [str(resp1),str(resp2)]

if __name__ == '__main__':
    import netaddr
    import sys
    import time
    from cssh_lib import csshpw
    #
    x=Infoblox(iba_password=csshpw())
    host = 'API-test-entry'
    resp1=x.get_next_available_ip("10.246.124.0/22")
    resp2=x.get_next_available_ip("10.246.132.0/22")
    newip1=str(resp1)
    newip2=str(resp2)
    dec1 = int(netaddr.IPAddress(newip1))
    dec2 = int(netaddr.IPAddress(newip2))
    print "DELTA:",dec2-dec1
    if (dec2-dec1) == 2048:
        print "Adding:", newip1, newip2
        #"""
        resp1=x.create_host_record(newip1,'%s-tun100' % host)
        resp2=x.create_host_record(newip2,'%s-tun200' % host)
        print resp1,resp2
        print 'Check InfoBlox: sleeping 20 seconds'
        time.sleep (20)
        resp1=x.delete_host_record(newip1)
        resp2=x.delete_host_record(newip2)
        #"""
    else:
        raise Exception()
    


