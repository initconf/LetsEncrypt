module LetsEncrypt;

#redef exit_only_after_terminate=T ; 
export {

	global letsencrypt_feed = fmt ("%s/feeds/LetsEncrypt.list",@DIR) &redef ; 
	
	type letsencrypt_ip: record {
		IP: addr ; 
	}; 
	
	type letsencrypt_val: record {
		IP: addr ; 
	}; 

	global letsencrypt_iplist: table[addr] of letsencrypt_val=table() ; 

} 

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )
event zeek_init()
{

Input::add_table([$source=letsencrypt_feed, $name="letsencrypt_feed", $idx=letsencrypt_ip, 
			$val=letsencrypt_val,  $destination=letsencrypt_iplist, $mode=Input::REREAD]);
}


event zeek_done()
{
	print fmt ("values in table %s", letsencrypt_iplist); 
} 

@endif 
