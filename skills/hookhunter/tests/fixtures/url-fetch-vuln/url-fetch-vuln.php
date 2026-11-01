<?php
/** Plugin Name: Fixture URL fetching (vulnerable) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'wp_ajax_nopriv_fx_url', 'fx_url' );

function fx_url() {
	$ch = curl_init( $_POST['url'] ); // VULN
	curl_exec( $ch );
	$tmp = download_url( $_POST['file'] ); // VULN
	media_sideload_image( $_POST['img'], 0 ); // VULN
	$feed = fetch_feed( $_GET['feed'] ); // VULN
	wp_send_json_success( $tmp );
}
