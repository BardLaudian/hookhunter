<?php
/** Plugin Name: Fixture SSRF (vulnerable) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'wp_ajax_nopriv_fx_fetch', 'fx_fetch' );

function fx_fetch() {
	$resp = wp_remote_get( $_POST['url'] ); // VULN
	$ch = curl_init();
	curl_setopt( $ch, CURLOPT_URL, $_GET['u'] ); // VULN
	curl_exec( $ch );
	wp_send_json( wp_remote_retrieve_body( $resp ) );
}
