module LetsEncrypt ;

@load files/x509/log-ocsp


global letsencrypt_hosts : pattern = /letsencrypt/ &redef ; 

export {
	redef enum Notice::Type += {
                OCSPPost,	
	}; 
} 

event zeek_init()
{
	Files::register_for_mime_type(Files::ANALYZER_OCSP_REQUEST, "application/ocsp-request");
        Files::register_for_mime_type(Files::ANALYZER_OCSP_REPLY, "application/ocsp-response");
} 

#event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=3
#{
    # Is it a POST & one we want to look at
    #if ( method == "POST") 
    #    {
    #	print fmt ("Method: %s, unescaped_URI: %s", method, unescaped_URI); 
    #    }
#}

# Process the response code from the server
event http_reply(c: connection, version: string, code: count, reason: string)
{
	local method = c$http?$method ? c$http$method : "" ; 
	local host = c$http?$host ? c$http$host : "" ; 
	local ip = c$id$resp_h; 
	print fmt ("%s", ip); 

	if (method == "POST" && letsencrypt_hosts in host) 
	{ 
		if (ip in LetsEncrypt::letsencrypt_iplist)
                return ;

		local n: Notice::Info = ([$note=OCSPPost, $src=ip, $conn=c, $msg= fmt ("LetsEncrypt OCSP server: %s", host), $identifier=cat(ip), $suppress_for=1 day]); 
		event LetsEncrypt::new_ip_seen(n); 
	} 
}
