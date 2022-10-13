<?php
/*
Plugin Name: JWT Authentication Whitelist 
Description: Allows Zapier to connect with Paid Memberships Pro
Version: 1.0.1
Author: Carter & Custer
Author URI: https://carterandcuster.com
Plugin URI: https://carterandcuster.com
License: GPLv2 or later
*/

$_candc_jwt_request_uri = untrailingslashit( parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH ) );
$_candc_jwt_user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';

$_candc_jwt_uri_whitelist = array( 
								// '/wp-json/pmpro/*',
							);

$_candc_jwt_user_agent_whitelist = array( 
										'Zapier',
									);			

add_filter( 'option_active_plugins', function( $plugins ){

	global  $_candc_jwt_request_uri,
			$_candc_jwt_user_agent,
			$_candc_jwt_uri_whitelist,
			$_candc_jwt_user_agent_whitelist;

	$is_whitelisted = false;

	// Check each URI in the whitelist 
	foreach( $_candc_jwt_uri_whitelist as $path ){

		// If the endpoint doesn't contain * symbol
		if ( false === stripos( $path, '*' ) ) {
			if ( $path === $_candc_jwt_request_uri ) {
				$is_whitelisted = true;
			}
		} else {
			$regex = '/' . str_replace( '/', '\/', $path ) . '/';

			if ( preg_match( $regex, $_candc_jwt_request_uri ) ) {
				$is_whitelisted = true;
			}
		}
	}

	// Check each User-Agent in the whitelist
	if ($_candc_jwt_user_agent) {
		foreach( $_candc_jwt_user_agent_whitelist as $user_agent ){
			if ( $_candc_jwt_user_agent === $user_agent ) {
				$is_whitelisted = true;
			}
		}
	}


	$plugin_to_deactivate = "jwt-authentication-for-wp-rest-api/jwt-auth.php";

	$k = array_search( $plugin_to_deactivate, $plugins );

	// Deactivate the JWT auth plugin if the request uri matches
	if ( false !== $k && false !== $is_whitelisted ){
		unset( $plugins[$k] );
	}

	return $plugins;

});