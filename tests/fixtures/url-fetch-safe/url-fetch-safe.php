<?php
/** Plugin Name: Fixture URL fetching (safe twin) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'wp_ajax_nopriv_fx_url', 'fx_url' );

function fx_url() {
	$url = esc_url_raw( $_POST['url'] );
	if ( ! wp_http_validate_url( $url ) ) {
		wp_send_json_error();
	}
	$ch = curl_init( $url ); // SAFE
	curl_exec( $ch );
	$tmp = download_url( 'https://api.example.test/file.zip' ); // SAFE
	wp_send_json_success( $tmp );
}
