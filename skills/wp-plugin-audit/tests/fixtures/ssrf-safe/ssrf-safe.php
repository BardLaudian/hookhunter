<?php
/** Plugin Name: Fixture SSRF (safe twin) */
/** Synthetic fixture for wp-plugin-audit tests. Not derived from any real plugin. */
add_action( 'wp_ajax_nopriv_fx_fetch', 'fx_fetch' );

function fx_fetch() {
	$url = esc_url_raw( $_POST['url'] );
	if ( ! wp_http_validate_url( $url ) ) {
		wp_send_json_error();
	}
	$resp  = wp_safe_remote_get( $url ); // SAFE
	$resp2 = wp_remote_get( $url ); // SAFE
	wp_send_json( wp_remote_retrieve_body( $resp ) . wp_remote_retrieve_body( $resp2 ) );
}
