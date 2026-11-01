<?php
/** Plugin Name: Fixture privilege escalation (safe twin) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'wp_ajax_fx_role', 'fx_role' );
add_action( 'admin_enqueue_scripts', function () {
	wp_localize_script( 'fx', 'fxData', array( 'nonce' => wp_create_nonce( 'fx_role' ) ) );
} );

function fx_role() {
	check_ajax_referer( 'fx_role' );
	if ( ! current_user_can( 'promote_users' ) ) {
		wp_send_json_error( null, 403 );
	}
	if ( in_array( $_POST['role'], array( 'subscriber', 'contributor' ), true ) ) {
		wp_update_user( array( 'ID' => (int) $_POST['id'], 'role' => $_POST['role'] ) ); // SAFE
	}
	wp_send_json_success();
}
