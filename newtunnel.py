def newtunnel (username,sitename):
    from ibx_lib import Infoblox
    from netaddr import IPAddress
    import sys
    import time
    from cssh_lib import csshpw

    x=Infoblox(iba_password=csshpw())
    resp=x.get_next_available_ip("10.246.124.0/22")
    newip1=str(resp)
    print "Adding:", newip1
    resp1=x.create_host_record(newip1,'%s-tun-100' % sitename)
    print 'Created:',resp1
    ###
    resp2=x.get_next_available_ip("10.246.132.0/22")
    newip2=str(resp2)
    print "Adding:", newip2
    resp3=x.create_host_record(newip2,'%s-tun-200' % sitename)
    print 'Created:',resp3
    #
    return( [str(IPAddress(newip1)) ,str(IPAddress(newip2)) ] )
            

if __name__ == '__main__':
    
    username=raw_input('username:').strip()
    if username=='':
        username='tgraham'
    sitename=raw_input("hostname:").strip()
    n = newtunnel (username,sitename)
    print n
            
    
