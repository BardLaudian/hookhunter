<?php
/** Plugin Name: Fixture information disclosure (vulnerable) */
/** Synthetic fixture for wp-plugin-audit tests. Not derived from any real plugin. */
add_action( 'wp_ajax_nopriv_fx_dump', 'fx_dump' );

function fx_dump() {
	phpinfo(); // VULN
	$users = get_users(); // VULN
	wp_send_json_success( $users );
}
