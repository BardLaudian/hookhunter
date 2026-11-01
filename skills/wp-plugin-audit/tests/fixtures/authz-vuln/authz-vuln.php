<?php
/** Plugin Name: Fixture missing capability check (vulnerable) */
/** Synthetic fixture for wp-plugin-audit tests. Not derived from any real plugin. */
add_action( 'wp_ajax_fx_save', 'fx_save' );
add_action( 'admin_enqueue_scripts', function () {
	wp_localize_script( 'fx', 'fxData', array( 'nonce' => wp_create_nonce( 'fx_save' ) ) );
} );

function fx_save() {
	check_ajax_referer( 'fx_save' );
	update_option( 'fx_title', sanitize_text_field( $_POST['t'] ) ); // VULN
	wp_send_json_success();
}
