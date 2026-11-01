<?php
/** Plugin Name: Fixture privilege escalation (vulnerable) */
/** Synthetic fixture for wp-plugin-audit tests. Not derived from any real plugin. */
add_action( 'wp_ajax_fx_role', 'fx_role' );

function fx_role() {
	check_ajax_referer( 'fx_role' );
	wp_update_user( array( 'ID' => (int) $_POST['id'], 'role' => $_POST['role'] ) ); // VULN
	update_user_meta( (int) $_POST['id'], 'wp_capabilities', $_POST['caps'] ); // VULN
	wp_send_json_success();
}
