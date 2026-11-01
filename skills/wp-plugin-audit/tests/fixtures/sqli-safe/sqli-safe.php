<?php
/** Plugin Name: Fixture SQLi (safe twin) */
/** Synthetic fixture for wp-plugin-audit tests. Not derived from any real plugin. */
add_action( 'wp_ajax_nopriv_fx_find', 'fx_find' );

function fx_find() {
	global $wpdb;
	$id   = absint( $_GET['id'] );
	$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}fx WHERE id = %d", $id ) ); // SAFE
	$total = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->posts}" ); // SAFE
	wp_send_json( array( 'rows' => $rows, 'total' => $total ) );
}
