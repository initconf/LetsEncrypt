module LetsEncrypt ;

export {

	redef enum Notice::Type += { 
		ValidationServer, 
		UserAgent, 
	} ; 

	global letsencrypt_URI: pattern = /\.well-known\/acme-challenge/ &redef ; 
	global letsencrypt_user_agents: pattern = /Let\'s Encrypt validation server; \+https\:\/\/www\.letsencrypt\.org/ &redef ; 

	global ip_seen:event(n: Notice::Info );  

	
} 


@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )
export { 

	global f=open_for_append( fmt("%s/feeds/LetsEncrypt.list",@DIR)); 
} 
@endif 
@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )
event zeek_init()
{
	Broker::auto_publish(Cluster::manager_topic, LetsEncrypt::ip_seen);
} 
@endif 


@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )
event ip_seen(n: Notice::Info ) 
{
	local ip = n$src ; 

	if (ip in LetsEncrypt::letsencrypt_iplist)
		return ; 

	NOTICE(n) ; 
	print f, ip ; 
}
@endif 

	
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=3
{
        local url = HTTP::build_url_http(c$http);
        local message = fmt("%s %s", c$http$method, url);

        if ( letsencrypt_URI in unescaped_URI )
        {
	local n: Notice::Info; 

	n$src=c$id$orig_h ; 
	n$conn=c; 
	n$note=LetsEncrypt::ValidationServer; 
	n$msg=message; 
	n$conn=c;
	n$identifier=cat(c$id$orig_h);
	n$suppress_for=1 day;
	event LetsEncrypt::ip_seen(n); 

        }
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=5
{
        if ( name == "USER-AGENT"  && letsencrypt_user_agents in value )
        {
		local n:Notice::Info; 
		n$note=UserAgent;
		n$conn=c;
	 	n$src=c$id$orig_h; 
		$msg=fmt("LetsEncrypt User-agent %s seen from %s", value, c$id$orig_h); 
		$identifier=cat(c$id$orig_h);
		n$suppress_for=1 day; 
	
		event LetsEncrypt::ip_seen(n); 
	}
 }

