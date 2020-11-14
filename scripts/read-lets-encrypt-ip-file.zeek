module LetsEncrypt;

export { 

	global LetsEncrypt::delay_zeek_init: event(); 
} 


@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )
event readline(description: Input::TableDescription, tpe: Input::Event, left: letsencrypt_ip, right: letsencrypt_val)
{
     	if ( tpe == Input::EVENT_NEW ) {
		log_reporter(fmt ("New: %s, right %s", left, right),0); 
		event LetsEncrypt::known_ip(left$IP); 
        }

        #if (tpe == Input::EVENT_CHANGED) {
        #                print fmt ("CHANGED");
        #}


        #if (tpe == Input::EVENT_REMOVED ) {
        #                print fmt ("REMOVED");
        #}

}

event LetsEncrypt::delay_zeek_init()
{

log_reporter(fmt("running delayed zeek_init to read table"),0); 
Input::add_table([$source=letsencrypt_feed, $name="letsencrypt_feed", $idx=letsencrypt_ip, 
			$val=letsencrypt_val,  $destination=letsencrypt_iplist, $mode=Input::REREAD, $ev=readline]);
}


event zeek_init()
{
	log_reporter(fmt("running zeek_init to read table"),0); 
	schedule 30 secs { LetsEncrypt::delay_zeek_init() }; 

} 

@endif 
