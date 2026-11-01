<?php
/** Plugin Name: Fixture missing capability check (safe twin) */
/** Synthetic fixture for wp-plugin-audit tests. Not derived from any real plugin. */
add_action( 'wp_ajax_fx_save', 'fx_save' );

function fx_save() {
	check_ajax_referer( 'fx_save' );
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( null, 403 );
	}
	update_option( 'fx_title', sanitize_text_field( $_POST['t'] ) ); // SAFE
	wp_send_json_success();
}
