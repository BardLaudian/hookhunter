<?php
/** Plugin Name: Fixture information disclosure (safe twin) */
/** Synthetic fixture for wp-plugin-audit tests. Not derived from any real plugin. */
add_action( 'wp_ajax_fx_dump', 'fx_dump' );

function fx_dump() {
	if ( ! current_user_can( 'list_users' ) ) {
		wp_send_json_error( null, 403 );
	}
	$users = get_users( array( 'fields' => array( 'display_name' ) ) ); // SAFE
	wp_send_json_success( $users );
}
