module LetsEncrypt; 

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )
export {

	redef enum Notice::Type += {
       		Whitelisted, 
	} ;


        global fname= fmt ("%s/feeds/LetsEncrypt.list", @DIR); 
        global f=open_for_append(fname); 
	global letsencrypt_feed = fname &redef ;
	global LetsEncrypt::add_to_whitelist: event(ip: addr); 
}
@endif

export {


        type letsencrypt_ip: record {
                IP: addr ;
        };

        type letsencrypt_val: record {
                IP: addr ;
        };

        global letsencrypt_iplist: table[addr] of letsencrypt_val=table() ;

}

export { 

        global LetsEncrypt::new_ip_seen:event(n: Notice::Info );
        global LetsEncrypt::known_ip: event(ip: addr) ;
	global log_reporter:function(msg: string, debug: count); 

}

function log_reporter(msg: string, debug: count)
{

        if (debug < 10)
               return ;

       @if ( ! Cluster::is_enabled())
        print fmt("%s", msg);
       @endif

        event reporter_info(network_time(), msg, peer_description);

}


@if ( Cluster::is_enabled() )

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event zeek_init()
{
        Broker::auto_publish(Cluster::worker_topic, LetsEncrypt::known_ip);

}
@else
event zeek_init()
{
        Broker::auto_publish(Cluster::manager_topic, LetsEncrypt::new_ip_seen);
}
@endif
@endif 

@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER)|| ! Cluster::is_enabled() )
event LetsEncrypt::known_ip (src: addr)
{
	log_reporter(fmt("LetsEncrypt::known_ip: %s", src),0); 

        if (src !in LetsEncrypt::letsencrypt_iplist)
        {
                local a : letsencrypt_val ;
                a$IP  = src ;
                letsencrypt_iplist[src] = a ;
        }

}
@endif

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )
event LetsEncrypt::add_to_whitelist(ip: addr)
{

	# following is LBL central to automatically add to
	# whitelist 

  	#local run_cmd = fmt ("/YURT/bin/bro-add-whitelist %s -c \"AUTOMATED ZEEK adding LetsEncrypt IP\"", ip); 
        #log_reporter(fmt ("%s", run_cmd), 21);
	#system(run_cmd); 	
	NOTICE([$note=Whitelisted, $src=ip,  $msg=fmt ("LetsEncrypt IP Whitelisted: %s",ip)]);

        #when ( local res = Exec::run([$cmd=run_cmd]))
        #{
	#	if (res?$stdout) 
	#		local out = res$stdout ; 
 	#	NOTICE([$note=Whitelisted, $src=ip,  $msg=fmt ("LetsEncrypt IP Whitelisted: %s,%s",ip, out)]);
        #}
        #timeout 5 mins 
        #{
        #	log_reporter(fmt ("Failed: %s, Result: ", run_cmd), 21);
        #}
} 

event LetsEncrypt::new_ip_seen(n: Notice::Info )
{
	log_reporter(fmt("LetsEncrypt::new_ip_seen: %s", n),0); 
        local ip = n$src ;

        if (ip in LetsEncrypt::letsencrypt_iplist)
                return ;
	
	if (ip !in LetsEncrypt::letsencrypt_iplist)
        {
                local a : letsencrypt_val ;
                a$IP  = ip ;
                letsencrypt_iplist[ip] = a ;
        }	

        NOTICE(n) ;
        print f, ip ;
	flush_all(); 
	event LetsEncrypt::add_to_whitelist(ip); 
	
}
@endif
